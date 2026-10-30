"""Evidence Report (spec section 11): a short, commit-pinned, verifiable summary for a skeptical engineer.

The report carries a SHA-256 digest of its deterministic results (graph shape, findings, readiness
checks, tool versions) and the commit hash. `lantern verify` re-runs the analysis on the same commit
and compares digests. The digest proves the results match the code; it is not a signature.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import html
import json
import platform
import re
import shutil
import subprocess
from pathlib import Path

from . import SCHEMA_VERSION, __version__
from .depaudit import NOTHING_TO_CHECK
from .graph import Graph
from .security import ID_VERSION

EVIDENCE_VERSION = 1
NARRATIVES_FILE = "lantern-narratives.md"


# ---------------------------------------------------------------------------- facts

def git_info(repo: Path) -> dict:
    git = shutil.which("git")
    if not git:
        return {"commit": None, "note": "git not installed"}

    def run(*args):
        try:
            p = subprocess.run([git, "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=20)
            return p.stdout.strip() if p.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    commit = run("rev-parse", "HEAD")
    if not commit:
        return {"commit": None, "note": "not a git repository"}
    dirty = run("status", "--porcelain", "--untracked-files=no")
    remote = run("config", "--get", "remote.origin.url") or ""
    remote = re.sub(r"//[^@/]+@", "//", remote)  # never echo credentials embedded in a remote URL
    return {"commit": commit, "branch": run("rev-parse", "--abbrev-ref", "HEAD"), "dirty": bool(dirty),
            "remote": remote or None, "committed_at": run("log", "-1", "--format=%cI")}


def tool_versions(sec: dict | None) -> list[dict]:
    rows = [{"tool": "lantern", "version": __version__, "role": "graph, bridge, web rules, readiness"},
            {"tool": "python", "version": platform.python_version(), "role": "runtime"}]
    try:
        from importlib.metadata import version
        for pkg in ("tree-sitter", "tree-sitter-python", "tree-sitter-typescript", "tree-sitter-javascript"):
            try:
                rows.append({"tool": pkg, "version": version(pkg), "role": "parser"})
            except Exception:  # noqa: BLE001 - optional package metadata
                pass
    except ImportError:
        pass
    for t in (sec or {}).get("tools", []):
        rows.append({"tool": t.get("tool"), "version": t.get("version"), "role": "scanner", "status": t.get("status")})
    return rows


def run_options(sec: dict | None, run_meta: dict | None) -> dict:
    """How the results were made, so `lantern verify` can make them the same way."""
    return {"scan": sec is not None, "trace": ((run_meta or {}).get("trace") or {}).get("command"),
            "offline": bool((run_meta or {}).get("offline"))}


def digest_payload(g: Graph, sec: dict | None, rd: dict | None, commit: str | None, dirty: bool = False,
                   run: dict | None = None) -> dict:
    """The deterministic part of the results. Same code + same tool versions + same run options -> same payload."""
    st = g.stats()
    return {
        "evidence_version": EVIDENCE_VERSION, "schema": SCHEMA_VERSION, "lantern": __version__, "commit": commit,
        "uncommitted_changes": bool(dirty), "run": run or {"scan": sec is not None, "trace": None},
        "graph": {"files": g.meta.get("files"), "lines": g.meta.get("lines"),
                  "nodes": st.get("nodes"), "call_edges": st.get("call_edges"),
                  "entry_points": sorted(f"{(n.entry or {}).get('kind')}:{(n.entry or {}).get('detail')}"
                                         for n in g.entry_points()),
                  "bridge": {k: v for k, v in (g.meta.get("bridge") or {}).items() if isinstance(v, int)}},
        "findings": sorted(f"{f['id']}:{f['rule']}:{f['rank']}:{f.get('status', 'open')}"
                           for f in (sec or {}).get("findings", [])),
        "scanners": sorted(f"{t.get('tool')}:{t.get('version')}:{(t.get('status') or '')[:2]}"
                           for t in (sec or {}).get("tools", [])),
        "readiness": None if not rd else {
            "score": rd["score"], "checks": sorted(f"{c['id']}:{c['status']}" for cat in rd["categories"]
                                                   for c in cat["checks"]),
            "protections": sorted(f"{x['id']}:{x['status']}" for x in rd.get("protections") or [])},
    }


def digest(payload: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def limits(g: Graph, sec: dict | None, rd: dict | None, run_meta: dict, privacy: str, exp: dict | None) -> list[str]:
    st = g.stats()
    out = [
        "Business-logic flaws. Scanners and graph checks find known patterns; they can't tell whether your "
        "rules (who may see what, what a price should be) are right.",
        f"Calls Lantern could not trace. {st.get('unresolved_call_sites', 0)} call sites were left unresolved "
        "rather than guessed, mostly calls into libraries or very dynamic code (getattr, plugins, "
        "hooks returning objects).",
    ]
    if st.get("guessed_by_method_name"):
        out.append(f"{st['guessed_by_method_name']} call edges were linked by method name alone because the object's "
                   "type was unknown. They are marked likely or possible, never confirmed, and can point at the "
                   "wrong function.")
    tr = run_meta.get("trace")
    if tr:
        out.append(f"Runtime behavior beyond what `{' '.join(tr.get('command', []))}` exercised. Python calls seen "
                   "running are marked observed; everything else is static.")
    else:
        out.append("Runtime behavior. No code was run for this report, so every edge is from static analysis and "
                   "tests were not executed.")
    if "typescript/javascript" in (g.meta.get("languages") or {}):
        out.append("Frontend call edges are static only (no JavaScript runtime tracing yet).")
    if sec is None:
        out.append("Security scanners were not run for this report (--no-scan): no findings does not mean no problems.")
    for t in (sec or {}).get("tools", []):
        st = str(t.get("status") or "")
        if t.get("tool") in ("pip-audit", "npm-audit") and st != "ok" and st not in NOTHING_TO_CHECK:
            lang = "Python" if t["tool"] == "pip-audit" else "npm"
            out.append(f"{lang} dependencies were not fully checked for known vulnerabilities ({st}).")
        if t.get("tool") == "pip-audit" and t.get("unpinned"):
            out.append(f"{t['unpinned']} Python requirement(s) give a range, not an exact version, so they were not "
                       "checked for known vulnerabilities. A lock file fixes this.")
    if any(f.get("category") == "dependency" for f in (sec or {}).get("findings", [])) or any(
            t.get("tool") in ("pip-audit", "npm-audit") and t.get("status") == "ok" for t in (sec or {}).get("tools", [])):
        out.append("Dependency findings come from live vulnerability databases, so a re-check can find new ones "
                   "without any code change.")
    heur = sum(1 for f in (sec or {}).get("findings", []) if f.get("tool_confidence") == "LOW")
    if heur:
        out.append(f"{heur} finding{'s are' if heur != 1 else ' is'} from heuristic checks that can misfire; they are "
                   "labeled as such.")
    if rd:
        out.append("The readiness score uses file and pattern checks. A check passing means the thing exists, not "
                   "that it is configured well.")
    if exp and exp.get("explanations"):
        out.append("Plain-language explanations were written by a model. Each phrase is checked to anchor to real "
                   "code, but the wording itself is not proof. The results digest does not cover explanations or "
                   "which model wrote them.")
    if privacy != "full":
        out.append("Source code was left out of this report (structure-only privacy).")
    return out


# ---------------------------------------------------------------------------- build

def build(g: Graph, sec: dict | None, rd: dict | None, exp: dict | None, run_meta: dict | None,
          baseline: dict | None, privacy: str = "full") -> dict:
    repo = Path(g.repo_root)
    run_meta = run_meta or {}
    gi = git_info(repo)
    findings = (sec or {}).get("findings", [])
    live = [f for f in findings if not f.get("in_tests")]
    fixed, changed = compare_baseline(findings, baseline)
    narratives = None
    nf = repo / NARRATIVES_FILE
    if nf.exists():
        narratives = nf.read_text(encoding="utf-8", errors="replace")[:20000]
    entries = [{"kind": (n.entry or {}).get("kind"), "detail": (n.entry or {}).get("detail"), "name": n.qualname,
                "file": n.file} for n in g.entry_points() if (n.entry or {}).get("kind") != "test"]
    models = []
    if exp and exp.get("stats"):
        s = exp["stats"]
        models.append({"model": s.get("model"), "task": "Three-Lens explanations", "validated": s.get("validated"),
                       "failed": s.get("failed"), "prompt_version": next(
                           (r.get("prompt_version") for r in exp.get("explanations", {}).values()), None)})
    payload = digest_payload(g, sec, rd, gi.get("commit"), gi.get("dirty", False), run_options(sec, run_meta))
    return {
        "evidence_version": EVIDENCE_VERSION,
        "header": {"repo": gi.get("remote") or repo.name, "name": repo.name, **gi,
                   "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                   "mode": "local", "privacy": privacy},
        "scorecard": {
            "readiness": None if not rd else {"score": rd["score"], "grade": rd["grade"], "shape": rd["shape"],
                                              "categories": [{k: c[k] for k in ("title", "weight", "score", "percent")}
                                                             for c in rd["categories"]]},
            "now": {k: sum(1 for f in live if f["rank"] == k and f.get("status") == "open")
                    for k in ("critical", "high", "medium", "low")},
            "before": (baseline or {}).get("counts"), "baseline_date": (baseline or {}).get("date"),
            "baseline_commit": (baseline or {}).get("commit"),
        },
        "architecture": {
            "languages": g.meta.get("languages"), "files": g.meta.get("files"), "lines": g.meta.get("lines"),
            "entries": entries, "bridge": g.meta.get("bridge"),
            "advice": (rd or {}).get("advice", []), "shape": (rd or {}).get("shape"),
            "frameworks": ((rd or {}).get("stack") or {}).get("frameworks", []),
            "edges": g.stats().get("confidence"),
        },
        "security": {
            "open": [_f(f) for f in live if f.get("status") == "open"],
            "accepted": [_f(f) | {"accepted": f.get("accepted")} for f in findings if f.get("status") == "accepted"],
            "fixed": fixed, "changed": changed, "in_tests": sum(1 for f in findings if f.get("in_tests")),
            "protections": [{k: x.get(k) for k in ("id", "title", "status", "why", "evidence", "how")}
                            for x in (rd or {}).get("protections") or []],
        },
        "understanding": narratives,
        "provenance": {"tools": tool_versions(sec), "models": models,
                       "rules": ["bandit default profile", "lantern-web LW-*/LJ-* rules", "lantern secret patterns",
                                 f"readiness checks v{(rd or {}).get('version', '-')}", f"graph schema {SCHEMA_VERSION}"]},
        "limits": limits(g, sec, rd, run_meta, privacy, exp),
        "digest": digest(payload), "payload": payload,
    }


def compare_baseline(findings: list[dict], baseline: dict | None) -> tuple[list[dict], list[dict]]:
    """Baseline findings that are gone. A gone finding counts as fixed only if the same rule doesn't show up as a
    new finding in the same file; otherwise the flagged line was probably edited or moved, so it is listed as
    "changed, still open" and never as fixed. Baselines from before stable ids can't be compared."""
    if not baseline or baseline.get("id_version") != ID_VERSION:
        return [], []
    old = baseline.get("findings") or {}
    cur_ids = {f["id"] for f in findings}
    new_by_place = {(f.get("rule"), f.get("file")) for f in findings if f["id"] not in old and not f.get("in_tests")}
    fixed, changed = [], []
    for k, v in old.items():
        if k in cur_ids:
            continue
        (changed if (v.get("rule"), v.get("file")) in new_by_place else fixed).append(dict(v, id=k))
    return fixed, changed


def _f(f: dict) -> dict:
    return {k: f.get(k) for k in ("id", "rank", "rule", "tool", "title", "file", "line", "tool_confidence")} | {
        "path": f.get("ui_path") or (f.get("reachable") or {}).get("path")}


def baseline_from(sec: dict | None, commit: str | None) -> dict:
    live = [f for f in (sec or {}).get("findings", []) if not f.get("in_tests")]
    return {"date": dt.date.today().isoformat(), "commit": commit, "id_version": ID_VERSION,
            "counts": {k: sum(1 for f in live if f["rank"] == k and f.get("status") == "open")
                       for k in ("critical", "high", "medium", "low")},
            "findings": {f["id"]: {"rule": f["rule"], "rank": f["rank"], "title": f["title"], "file": f["file"],
                                   "line": f["line"]} for f in live}}


# ---------------------------------------------------------------------------- render

def badge_svg(score: int, grade: str) -> str:
    color = {"A": "#0D9488", "B": "#0D9488", "C": "#64748B", "D": "#B54708", "F": "#B42318"}.get(grade, "#64748B")
    right = f"{score}/100 {grade}"
    w1, w2 = 62, 12 + 7 * len(right)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w1 + w2}" height="20" role="img" '
            f'aria-label="Lantern readiness: {right}"><rect width="{w1}" height="20" fill="#0F1B2D"/>'
            f'<rect x="{w1}" width="{w2}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="8" y="14">lantern</text><text x="{w1 + 6}" y="14">{right}</text></g></svg>')


def E(v) -> str:
    """Escape anything for HTML. The renderer also runs on `evidence.json` read back from a repo folder, so no
    field is trusted to be the type or text we wrote."""
    return html.escape("" if v is None else str(v), quote=True)


def _trace_suffix(ev: dict) -> str:
    cmd = (((ev.get("payload") or {}).get("run") or {}).get("trace"))
    return " -- " + " ".join(map(str, cmd)) if isinstance(cmd, list) and cmd else ""


def _pct(v) -> float:
    return max(0.0, min(100.0, float(v))) if isinstance(v, (int, float)) else 0.0


def _deploy_svg(shape: str | None) -> str:
    boxes = {
        "full-stack web app": [("Browser", "your frontend (static / edge)"), ("API", "container, 2+ instances"),
                               ("Database", "managed, backups on")],
        "web API": [("Clients", "apps and services"), ("API", "container, 2+ instances"), ("Database", "managed")],
        "frontend web app": [("Browser", "visitors"), ("Edge / CDN", "static hosting"), ("APIs", "third-party services")],
        "command-line tool": [("Source", "tagged release"), ("CI", "build + test on 3 OSes"), ("Registry", "PyPI / npm")],
        "script or worker": [("Scheduler", "cron or queue"), ("Worker", "container, retries"), ("Logs", "kept 30+ days")],
        "library": [("Source", "tagged release"), ("CI", "tests"), ("Registry", "PyPI / npm")],
    }.get(shape or "", [])
    if not boxes:
        return ""
    w, bw, gap = 660, 180, 50
    parts = [f'<svg viewBox="0 0 {w} 90" width="100%" role="img" aria-label="Recommended deployment">',
             '<defs><marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
             'orient="auto"><path d="M0 0L10 5L0 10z" fill="currentColor"/></marker></defs>']
    for i, (t, sub) in enumerate(boxes):
        x = 10 + i * (bw + gap)
        parts.append(f'<rect x="{x}" y="15" width="{bw}" height="60" rx="10" fill="none" stroke="currentColor" '
                     f'stroke-opacity=".35"/><text x="{x + bw / 2}" y="41" text-anchor="middle" font-weight="700" '
                     f'font-size="14" fill="currentColor">{E(t)}</text><text x="{x + bw / 2}" y="60" '
                     f'text-anchor="middle" font-size="11" fill="currentColor" fill-opacity=".7">{E(sub)}</text>')
        if i:
            parts.append(f'<line x1="{x - gap + 4}" y1="45" x2="{x - 4}" y2="45" stroke="currentColor" '
                         f'marker-end="url(#a)"/>')
    return "".join(parts) + "</svg>"


def _narratives_html(text: str) -> str:
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        b = block.strip()
        m = re.match(r"^(#{1,4})\s+(.*)", b)
        if m and "\n" not in b:
            out.append(f"<h4>{E(m.group(2))}</h4>")
        else:
            out.append(f"<p>{E(b)}</p>".replace("\n", "<br>"))
    return "".join(out)


def render_html(ev: dict) -> str:
    h, sc, ar, se = ev["header"], ev["scorecard"], ev["architecture"], ev["security"]
    rd = sc["readiness"]
    commit = h.get("commit")
    commit_html = (f"<code>{E(commit[:12])}</code>" + (" <b class='warn'>with uncommitted changes</b>" if h.get("dirty") else "")
                   if commit else "<b class='warn'>not pinned: no git commit</b>")

    def cnt(d):
        return " · ".join(f"<span class='sev {k}'>{E(d.get(k, 0))} {k}</span>" for k in ("critical", "high", "medium", "low")) if d else "–"

    cats = "".join(f"<tr><td>{E(c['title'])}</td><td class='num'>{'n/a' if c['score'] is None else E(c['score'])}"
                   f"<span class='muted'>/{E(c['weight'])}</span></td><td><span class='bar'><i style='width:{_pct(c.get('percent'))}%'></i>"
                   f"</span></td></tr>" for c in (rd or {}).get("categories", []))
    entries = "".join(f"<li><span class='tag'>{E(e['kind'])}</span> <code>{E(e['detail'] or e['name'])}</code> "
                      f"<span class='muted'>{E(e['file'] or '')}</span></li>" for e in ar["entries"][:40])
    if len(ar["entries"]) > 40:
        entries += f"<li class='muted'>and {len(ar['entries']) - 40} more</li>"
    br = ar.get("bridge") or {}
    bridge = (f"<p>{E(br.get('matched', 0))} of {E(br.get('http_calls', 0))} frontend HTTP calls are linked to a backend "
              f"route in this repo; {E(br.get('external', 0))} go to external services.</p>" if br.get("http_calls") else "")

    def frow(f, extra=""):
        path = " → ".join(E(p.split("::")[-1].split(".")[-1]) for p in (f.get("path") or [])[:8])
        heur = " <span class='tag'>heuristic</span>" if f.get("tool_confidence") == "LOW" else ""
        return (f"<tr><td><span class='sev {E(f['rank'])}'>{E(f['rank'])}</span></td><td><b>{E(f['title'])}</b>{heur}<br>"
                f"<span class='muted'>{E(f.get('tool') or '')} {E(f['rule'])} · {E(f['file'] or '')}:{E(f.get('line') or '')}"
                f"</span>{'<br><span class=path>' + path + '</span>' if path else ''}{extra}</td></tr>")

    open_rows = "".join(frow(f) for f in se["open"]) or "<tr><td colspan=2 class='muted'>None.</td></tr>"
    acc_rows = "".join(frow(f, f"<div class='reason'>Accepted by {E(f['accepted'].get('by') or '?')} on "
                                f"{E(f['accepted'].get('date') or '?')}: {E(f['accepted'].get('reason') or '')}</div>")
                       for f in se["accepted"])
    changed_rows = "".join(f"<tr><td><span class='sev {E(f['rank'])}'>{E(f['rank'])}</span></td><td><b>{E(f['title'])}</b> "
                           f"<span class='tag'>changed · still open</span><br><span class='muted'>{E(f['rule'])} · "
                           f"{E(f['file'] or '')}</span></td></tr>" for f in se.get("changed") or [])
    fixed_rows = "".join(f"<tr><td><span class='sev {E(f['rank'])}'>{E(f['rank'])}</span></td><td><b>{E(f['title'])}</b> "
                         f"<span class='tag ok'>fixed · verified by rescan</span><br><span class='muted'>{E(f['rule'])} · "
                         f"{E(f['file'] or '')}:{E(f.get('line') or '')}</span></td></tr>" for f in se["fixed"])
    prot = [x for x in se.get("protections") or [] if isinstance(x, dict)]
    prot_word = {"add": "add", "check": "check", "in place": "in place"}
    prot_rows = "".join(
        f"<tr><td><span class='tag{' ok' if x.get('status') == 'in place' else ''}'>{prot_word.get(x.get('status'), 'check')}"
        f"</span></td><td><b>{E(x.get('title'))}</b><br><span class='muted'>{E(x.get('why'))}</span>"
        + (f"<br><span class='muted'>Evidence: {E(' · '.join(map(str, x.get('evidence') or [])))}</span>" if x.get("evidence") else "")
        + (f"<div class='reason'>{E(x.get('how'))}</div>" if x.get("status") != "in place" else "") + "</td></tr>" for x in prot)
    tools = "".join(f"<tr><td>{E(t['tool'] or '')}</td><td>{E(t.get('version') or '–')}</td><td class='muted'>"
                    f"{E(t.get('role') or '')}{(' · ' + E(t['status'])) if t.get('status') and t['status'] != 'ok' else ''}"
                    f"</td></tr>" for t in ev["provenance"]["tools"])
    models = "".join(f"<tr><td>{E(m['model'] or '')}</td><td>{E(m['task'])}</td><td class='muted'>{E(m.get('validated'))} "
                     f"validated, {E(m.get('failed'))} rejected · prompt {E(m.get('prompt_version') or '-')}</td></tr>"
                     for m in ev["provenance"]["models"]) or "<tr><td colspan=3 class='muted'>No model was used.</td></tr>"
    verify = (f"git checkout {commit[:12]} && pip install \"lantern[scan] @ git+https://github.com/LittleHenderson/Lantern\" "
              f"&& lantern verify . --report evidence.html{_trace_suffix(ev)}") if commit else "Commit your changes and regenerate the report to make it verifiable."
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidence Report · {E(h['name'])}</title>
<style>
:root{{--bg:#F6F7F9;--panel:#fff;--ink:#0F1B2D;--body:#334155;--muted:#64748B;--line:#E2E8F0;--soft:#F1F5F9;--accent:#0D9488;
--crit:#B42318;--crits:#FEF0EE;--high:#B54708;--highs:#FFF6E5;--med:#475467;--meds:#F2F4F7;--low:#0D9488;--lows:#E6F6F4}}
@media (prefers-color-scheme: dark){{:root{{--bg:#0B1220;--panel:#111A2B;--ink:#E6EDF6;--body:#C2CCDA;--muted:#8A97AB;--line:#22304A;--soft:#17223A;
--accent:#2DD4BF;--crit:#FDA29B;--crits:#3A1512;--high:#FEC84B;--highs:#33240B;--med:#CBD5E1;--meds:#1E293B;--low:#5EEAD4;--lows:#0E2E2B}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--body);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Inter","Segoe UI",Roboto,sans-serif}}
main{{max-width:860px;margin:0 auto;padding:24px 16px 60px}}
section{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:0 0 14px}}
h1{{color:var(--ink);font-size:22px;margin:0 0 4px}} h2{{color:var(--ink);font-size:15px;margin:0 0 10px;letter-spacing:.01em}}
h2 small{{color:var(--muted);font-weight:500}} h4{{color:var(--ink);margin:12px 0 4px}}
code{{font:12.5px ui-monospace,"SF Mono",Menlo,Consolas,monospace;background:var(--soft);padding:1px 5px;border-radius:5px;overflow-wrap:anywhere}}
.muted{{color:var(--muted)}} .warn{{color:var(--high)}}
.kv{{display:grid;grid-template-columns:150px 1fr;gap:4px 12px}} .kv div:nth-child(odd){{color:var(--muted)}}
.score{{display:flex;gap:18px;align-items:center;flex-wrap:wrap}} .big{{font-size:46px;font-weight:800;color:var(--ink);line-height:1}}
.grade{{font-size:22px;font-weight:800;width:46px;height:46px;border-radius:12px;display:grid;place-items:center;background:var(--soft);color:var(--ink)}}
table{{width:100%;border-collapse:collapse}} td{{padding:6px 6px;border-top:1px solid var(--line);vertical-align:top}}
td.num{{text-align:right;white-space:nowrap;width:70px;font-variant-numeric:tabular-nums}}
.bar{{display:block;height:8px;border-radius:99px;background:var(--soft);overflow:hidden;min-width:80px}} .bar i{{display:block;height:100%;background:var(--accent)}}
.sev{{display:inline-block;font-size:11px;font-weight:700;padding:0 7px;border-radius:99px;white-space:nowrap}}
.sev.critical{{background:var(--crits);color:var(--crit)}} .sev.high{{background:var(--highs);color:var(--high)}}
.sev.medium{{background:var(--meds);color:var(--med)}} .sev.low{{background:var(--lows);color:var(--low)}}
.tag{{display:inline-block;font-size:11px;padding:0 7px;border-radius:99px;border:1px solid var(--line);color:var(--muted)}} .tag.ok{{color:var(--low);border-color:var(--low)}}
.path{{font:11.5px ui-monospace,Menlo,monospace;color:var(--accent)}} .reason{{margin-top:4px;padding:6px 8px;background:var(--soft);border-radius:6px}}
ul{{padding-left:20px;margin:6px 0}} li{{margin:3px 0}}
.digest{{font:12px ui-monospace,Menlo,monospace;overflow-wrap:anywhere;color:var(--ink)}}
.diagram{{color:var(--ink);margin:10px 0}}
button.print{{float:right;font:inherit;font-size:12.5px;padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:var(--panel);color:var(--ink);cursor:pointer}}
@media print{{body{{background:#fff}} section{{break-inside:avoid;border-color:#ccc}} button.print{{display:none}}}}
@media (max-width:560px){{.kv{{grid-template-columns:1fr}} .kv div:nth-child(odd){{margin-top:6px}}}}
</style></head><body><main>
<section><button class="print" onclick="window.print()">Save as PDF</button>
<h1>Evidence Report</h1><div class="muted">{E(h['name'])} · made with Lantern {E(__version__)}</div>
<div class="kv" style="margin-top:12px"><div>Repository</div><div>{E(h['repo'] or '')}</div>
<div>Commit</div><div>{commit_html}{(' on ' + E(h['branch'])) if h.get('branch') else ''}</div>
<div>Analyzed</div><div>{E(h['generated_at'])}</div><div>Mode</div><div>local (the code never left this machine{', except to the model provider listed below' if ev['provenance']['models'] else ''})</div>
<div>Privacy level</div><div>{E(h['privacy'])}</div></div></section>

<section><h2>1 · Scorecard</h2>
{f'''<div class="score"><span class="big">{E(rd["score"])}<span style="font-size:20px" class="muted">/100</span></span><span class="grade">{E(rd["grade"])}</span>
<div class="muted">Deployment readiness for a {E(rd["shape"])}.<br>Checks that don't apply are skipped, not counted.</div></div>
<table style="margin-top:12px">{cats}</table>''' if rd else '<p class="muted">Readiness was not computed.</p>'}
<div class="kv" style="margin-top:14px"><div>Open findings now</div><div>{cnt(sc['now'])}</div>
<div>At first analysis</div><div>{cnt(sc['before'])}{(' <span class="muted">(' + E(sc['baseline_date'] or '') + ')</span>') if sc.get('before') else ''}</div></div></section>

<section><h2>2 · Architecture</h2>
<p>{E(ar['files'])} files, {E(ar['lines'])} lines{(' · ' + E(', '.join(ar['frameworks']))) if ar['frameworks'] else ''}.
{E(len(ar['entries']))} entry points: the places a user, a request, or a command can start running code.</p>
<ul>{entries}</ul>{bridge}
{f'<h4>Recommended deployment</h4><div class="diagram">{_deploy_svg(ar["shape"])}</div><ul>' + ''.join(f'<li>{E(a)}</li>' for a in ar['advice']) + '</ul>' if ar['advice'] else ''}
</section>

<section><h2>3 · Security <small>· ranked by severity and by whether a user can reach the code</small></h2>
<h4>Open ({len(se['open'])})</h4><table>{open_rows}</table>
{f"<h4>Fixed since first analysis ({len(se['fixed'])})</h4><table>{fixed_rows}</table>" if se['fixed'] else ''}
{f"<h4>Changed but still open ({len(se.get('changed') or [])})</h4><p class='muted'>The flagged line changed, and the same rule now flags new code in the same file, so these are not counted as fixed.</p><table>{changed_rows}</table>" if se.get('changed') else ''}
{f"<h4>Accepted risks ({len(se['accepted'])})</h4><table>{acc_rows}</table>" if se['accepted'] else ''}
{f"<h4>Protections to add ({sum(1 for x in prot if x.get('status') != 'in place')})</h4><p class='muted'>Heuristic: shown only where the code gives a reason; they don't change findings or the score.</p><table>{prot_rows}</table>" if prot else ''}
{f"<p class='muted'>{E(se['in_tests'])} more finding(s) are in test code only.</p>" if se['in_tests'] else ''}
</section>

<section><h2>4 · Understanding</h2>
{_narratives_html(ev['understanding']) if ev['understanding'] else f'<p class="muted">No path narratives attached. Write how your key flows work in <code>{NARRATIVES_FILE}</code> at the repository root and regenerate.</p>'}
</section>

<section><h2>5 · Provenance</h2><table>{tools}</table>
<h4>Models</h4><table>{models}</table>
<h4>Rule sets</h4><ul>{''.join(f'<li>{E(r)}</li>' for r in ev['provenance']['rules'])}</ul>
<p class="muted">Facts (call edges, findings, scores) come from the tools above. Models only explain; they never create or close a finding.</p></section>

<section><h2>6 · Limits <small>· what this report does not prove</small></h2><ul>{''.join(f'<li>{E(x)}</li>' for x in ev['limits'])}</ul></section>

<section><h2>7 · Verify it yourself</h2>
<p>Results digest: <span class="digest">{E(ev['digest'])}</span></p>
<p class="muted">This is a SHA-256 hash of the deterministic results above (graph, findings, readiness checks, tool versions) and the commit. Re-running the open-source analyzer on the same commit with the same tool versions gives the same digest. It shows the results match the code; it is not a signature of who made the report.</p>
<p><code>{E(verify)}</code></p></section>
</main></body></html>"""


def write(out_dir: Path, ev: dict) -> dict[str, Path]:
    paths = {"html": out_dir / "evidence.html", "json": out_dir / "evidence.json"}
    paths["html"].write_text(render_html(ev), encoding="utf-8")
    paths["json"].write_text(json.dumps(ev, indent=1), encoding="utf-8")
    rd = ev["scorecard"]["readiness"]
    if rd:
        paths["badge"] = out_dir / "badge.svg"
        paths["badge"].write_text(badge_svg(rd["score"], rd["grade"]), encoding="utf-8")
    return paths
