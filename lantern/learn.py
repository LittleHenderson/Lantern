"""Starter apps: small, deliberately imperfect apps a beginner creates, analyzes, and fixes step by step.

Each starter lives in `lantern/starters/<id>/`: `starter.json.tmpl` (title, steps, how each step is checked),
`files/` (the app as an AI assistant might first write it) and `solution/` (the fixed files). Every file there ends
in `.tmpl` (even the step texts, which name the planted secrets) and dot-files are stored as `dot.<name>`, so Lantern's own audit never mistakes the planted problems
for Lantern's code. Progress is computed from the results of a normal `lantern analyze`, never from a model.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).parent / "starters"
MARKER = ".lantern-starter"
ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,40}")
FEATURES = {"atlas", "findings", "ready", "evidence", "explain", "settings", "cli"}


def _decode(rel: Path) -> Path:
    parts = [p[3:] if p.startswith("dot.") else p for p in rel.parts]
    parts[-1] = parts[-1].removesuffix(".tmpl")
    return Path(*parts)


def ids() -> list[str]:
    return sorted(p.name for p in ROOT.iterdir() if (p / "starter.json.tmpl").is_file()) if ROOT.is_dir() else []


def get(sid: str) -> dict:
    if not isinstance(sid, str) or not ID_RE.fullmatch(sid) or sid not in ids():
        raise ValueError(f"unknown starter {sid!r}; choose one of: {', '.join(ids())}")
    d = json.loads((ROOT / sid / "starter.json.tmpl").read_text(encoding="utf-8"))
    d["id"] = sid
    return d


def catalog() -> list[dict]:
    """Starters for the Learn page and `lantern start`, without the long step texts."""
    keep = ("id", "title", "stack", "level", "minutes", "summary", "teaches", "order")
    out = []
    for sid in ids():
        s = get(sid)
        out.append({**{k: s.get(k) for k in keep}, "steps": [st["title"] for st in s["steps"]]})
    return sorted(out, key=lambda s: (s.get("order") or 99, s["id"]))


def template_files(sid: str, part: str = "files") -> dict[str, Path]:
    """Repo-relative path (posix) -> template file."""
    base = ROOT / sid / part
    if not base.is_dir():
        return {}
    return {_decode(p.relative_to(base)).as_posix(): p for p in sorted(base.rglob("*.tmpl")) if p.is_file()}


def scaffold(sid: str, dest: Path, solved: bool = False) -> list[str]:
    """Write the starter into `dest` (which must not exist or be empty). `solved` applies every fix."""
    s = get(sid)
    dest = Path(dest)
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise ValueError(f"{dest} already exists and isn't empty; Lantern never overwrites files")
    files = template_files(sid)
    if solved:
        files.update(template_files(sid, "solution"))
        for rel in s.get("solution_delete", []):
            files.pop(rel, None)
    for rel, src in files.items():
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(src.read_bytes())
    (dest / "TUTORIAL.md").write_text(tutorial_markdown(s), encoding="utf-8")
    (dest / MARKER).write_text(json.dumps({"starter": sid}) + "\n", encoding="utf-8")
    return sorted([*files, "TUTORIAL.md"])


def starter_of(repo: Path) -> str | None:
    """The starter a folder was created from, if its marker names one we ship (the marker itself may be planted,
    so only a known id is accepted and nothing else is read from it)."""
    try:
        sid = json.loads((Path(repo) / MARKER).read_text(encoding="utf-8")).get("starter")
    except (OSError, ValueError, AttributeError):
        return None
    return sid if isinstance(sid, str) and ID_RE.fullmatch(sid) and sid in ids() else None


def solution_text(sid: str, rel: str) -> str | None:
    """The fixed version of one file, from our own templates."""
    src = template_files(sid, "solution").get(rel)
    return src.read_text(encoding="utf-8") if src else None


# ---------------------------------------------------------------------------- progress

def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _rows(v) -> list[dict]:
    return [x for x in v if isinstance(x, dict)] if isinstance(v, list) else []


def check(cond: dict, repo: Path, out: Path) -> tuple[str, str]:
    """('done' | 'todo' | 'unknown', plain reason). Results files may be planted, so only shapes are trusted."""
    sec = _load(out / "security.json")
    findings = _rows((sec or {}).get("findings")) if isinstance(sec, dict) else []
    live = [f for f in findings if not f.get("in_tests")]

    def matching(f):
        return f.get("rule") in cond["rules"] and (not cond.get("match") or cond["match"] in str(f.get("title", "")))

    kind = cond.get("kind")
    if kind == "analyzed":
        return ("done", "analyzed") if (out / "readiness.json").exists() else ("todo", "not analyzed yet")
    if sec is None and kind in ("cleared", "accepted_or_cleared", "deps_clean"):
        return "unknown", "analyze the project first"
    if kind == "cleared":
        left = [f for f in live if matching(f) and f.get("status") != "accepted"]
        return ("todo", f"{len(left)} still open") if left else ("done", "no longer found")
    if kind == "accepted_or_cleared":
        left = [f for f in live if matching(f) and f.get("status") != "accepted"]
        return ("todo", f"{len(left)} still open") if left else ("done", "fixed or accepted with a reason")
    if kind == "deps_clean":
        tools = _rows(sec.get("tools"))
        ran = [t for t in tools if t.get("tool") in ("pip-audit", "npm-audit") and str(t.get("status", "")).startswith("ok")]
        left = [f for f in live if f.get("category") == "dependency" and f.get("status") != "accepted"]
        if left:
            return "todo", f"{len(left)} known vulnerabilities in dependencies"
        if not ran:
            return "unknown", "dependency check didn't run (offline?)"
        return "done", "no known vulnerabilities"
    if kind == "protection":
        rd = _load(out / "readiness.json")
        prot = {p.get("id"): p.get("status") for p in _rows((rd or {}).get("protections") if isinstance(rd, dict) else None)}
        missing = [i for i in cond["ids"] if prot.get(i) != "in place"]
        if rd is None:
            return "unknown", "analyze the project first"
        return ("todo", "still to add: " + ", ".join(missing)) if missing else ("done", "in place")
    if kind == "exists":
        missing = [f for f in cond["files"] if not any(Path(repo).glob(f))]
        return ("todo", "missing: " + ", ".join(missing)) if missing else ("done", "files present")
    if kind == "explained":
        ex = _load(out / "explanations.json")
        n = len(ex.get("explanations") or {}) if isinstance(ex, dict) and isinstance(ex.get("explanations"), dict) else 0
        return ("done", f"{n} explained") if n else ("todo", "nothing explained yet")
    if kind == "observed":
        g = _load(out / "graph.json")
        n = sum(1 for e in _rows((g or {}).get("edges") if isinstance(g, dict) else None) if e.get("confidence") == "observed")
        return ("done", f"{n} calls seen running") if n else ("todo", "no traced run yet")
    if kind == "fixed":
        ev = _load(out / "evidence.json")
        sec_ev = ev.get("security") if isinstance(ev, dict) else None
        n = sec_ev.get("fixed") if isinstance(sec_ev, dict) else None
        n = len(n) if isinstance(n, list) else 0
        return ("done", f"{n} findings fixed since the first analysis") if n else ("todo", "no fixes recorded yet")
    return "unknown", "checked by you"


def progress(sid: str, repo: Path, out: Path | None = None) -> dict:
    s = get(sid)
    out = Path(out) if out else Path(repo) / ".lantern"
    steps = []
    for i, st in enumerate(s["steps"], 1):
        status, why = check(st["check"], Path(repo), out) if st.get("check") else ("read", "")
        steps.append({"n": i, "id": st["id"], "title": st["title"], "status": status, "why": why})
    checkable = [x for x in steps if x["status"] != "read"]
    # `total` counts the steps Lantern can check; read-only steps ("explore the map") are listed but counted apart.
    return {"starter": sid, "title": s["title"], "steps": steps,
            "done": sum(1 for x in checkable if x["status"] == "done"), "total": len(checkable),
            "explore": len(steps) - len(checkable)}


# ---------------------------------------------------------------------------- text

def tutorial_markdown(s: dict) -> str:
    """TUTORIAL.md written next to the app: the same steps the Learn page shows."""
    lines = [f"# {s['title']}", "", s["summary"], "", f"**Stack:** {s['stack']} · **Time:** about {s['minutes']} minutes",
             "", "Open this folder in Lantern (`lantern serve .`) and use the **Guide** tab, or follow along here.", ""]
    if s.get("run"):
        lines += ["## Run the app (optional)", "", "```bash", *s["run"], "```", ""]
    for i, st in enumerate(s["steps"], 1):
        lines += [f"## Step {i}. {st['title']}", ""]
        for para in st["body"]:
            lines += [para, ""]
        if st.get("commands"):
            lines += ["```bash", *st["commands"], "```", ""]
        if st.get("prompt"):
            lines += ["Ask your AI assistant:", "", "> " + st["prompt"], ""]
        if st.get("fix_files"):
            lines += ["The fixed version of " + ", ".join(f"`{f}`" for f in st["fix_files"])
                      + " is in Lantern's Guide tab (\"Show the fix\"), or run `lantern learn --show-fix "
                      + f"{st['fix_files'][0]}` in this folder.", ""]
    return "\n".join(lines).rstrip() + "\n"
