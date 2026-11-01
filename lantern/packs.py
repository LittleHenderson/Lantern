"""Analysis packs: pattern files that teach Lantern new security rules and new framework entry points.

A pack is a JSON file, not code, so it cannot do anything to the machine or to the results beyond what this
module lets it: add findings from line patterns, and mark functions as entry points (routes, pages, commands)
so reachability, click paths and the login check cover a framework Lantern has no built-in support for.

Where packs come from (all are loaded; a project's and a user's packs count as third-party):
  * built in     lantern/packs/*.json           tested with the repo, shipped with Lantern
  * project      <repo>/lantern-packs/*.json    committed by the project (the repo is untrusted, like its code)
  * user         LANTERN_HOME/packs/*.json       ~/.lantern/packs by default

Format (see docs/packs.md):
  {"pack": "django", "version": "1", "about": "...",
   "requires": {"files": ["manage.py"], "text": ["django"]},          # optional: when the pack applies
   "rules":   [{"id": "LP-DJANGO-DEBUG", "title": "...", "severity": "MEDIUM", "cwe": 489,
                "files": ["**/settings*.py"], "pattern": "^\\s*DEBUG\\s*=\\s*True", "fix": "...", "more": "..."}],
   "entries": [{"kind": "route", "files": ["**/urls.py"],
                "pattern": "\\bpath\\(\\s*r?['\"]([^'\"]*)['\"]\\s*,\\s*([\\w.]+)", "detail": "ANY /{1}", "handler": "{2}"}]}

What a pack cannot do, by construction:
  * fake certainty: pack findings are marked heuristic (`tool_confidence: LOW`) unless the pack is built in and
    says `"confidence": "HIGH"`; pack entry points carry `via: pack:<name>`
  * close or change a finding: packs only add
  * run code or read outside the repo: patterns match one line at a time, in repo files Lantern already reads
  * hide: every pack in use is listed in the Evidence Report's provenance and by `lantern packs`
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from pathlib import Path

from .graph import Graph
from .python_frontend import SKIP_DIRS, inside_repo

BUILTIN_DIR = Path(__file__).parent / "packs"
PROJECT_DIR = "lantern-packs"
RULE_ID = re.compile(r"^LP-[A-Z0-9][A-Z0-9-]{1,40}$")
PACK_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
SEVERITIES = ("HIGH", "MEDIUM", "LOW")
ENTRY_KINDS = ("route", "page", "cli", "main")
MAX_RULES, MAX_ENTRIES, MAX_PATTERN, MAX_LINE, MAX_FILE = 60, 20, 400, 2000, 600_000
TEXT_EXTS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html", ".json",
             ".toml", ".yaml", ".yml", ".ini", ".cfg", ".env", ".txt", ".md", ".rb", ".php", ".go", ".rs", ".java",
             ".kt", ".cs", ".sql", ".prisma", ".graphql", ".tf", ".conf", ".xml", ".properties"}


def user_dir() -> Path:
    return Path(os.environ.get("LANTERN_HOME") or Path.home() / ".lantern") / "packs"


# ---------------------------------------------------------------------------- validation

def validate(pack: dict) -> list[str]:
    """Problems with a pack, as plain sentences. An empty list means it can be used."""
    errs = []
    if not isinstance(pack, dict):
        return ["a pack is a JSON object"]
    name = pack.get("pack")
    if not isinstance(name, str) or not PACK_NAME.match(name):
        errs.append("`pack` must be a short lowercase name (letters, digits, dashes)")
    if "version" in pack and not isinstance(pack["version"], (str, int)):
        errs.append("`version` must be a string")
    req = pack.get("requires", {})
    if not isinstance(req, dict) or any(not isinstance(req.get(k, []), list) for k in ("files", "text")):
        errs.append("`requires` must be an object with optional `files` and `text` lists")
    rules, entries = pack.get("rules", []), pack.get("entries", [])
    if not isinstance(rules, list) or not isinstance(entries, list):
        return errs + ["`rules` and `entries` must be lists"]
    if not rules and not entries:
        errs.append("a pack needs at least one rule or entry pattern")
    if len(rules) > MAX_RULES or len(entries) > MAX_ENTRIES:
        errs.append(f"at most {MAX_RULES} rules and {MAX_ENTRIES} entry patterns")
    seen = set()
    for i, r in enumerate(rules):
        w = f"rules[{i}]"
        if not isinstance(r, dict):
            errs.append(f"{w}: must be an object")
            continue
        rid = r.get("id")
        if not isinstance(rid, str) or not RULE_ID.match(rid):
            errs.append(f"{w}: `id` must look like LP-NAME (uppercase, starts with LP-)")
        elif rid in seen:
            errs.append(f"{w}: duplicate id {rid}")
        seen.add(rid)
        if not isinstance(r.get("title"), str) or not 3 <= len(r["title"]) <= 160:
            errs.append(f"{w}: `title` is a short sentence")
        if r.get("severity") not in SEVERITIES:
            errs.append(f"{w}: `severity` is HIGH, MEDIUM or LOW")
        errs += _check_pattern(r.get("pattern"), w)
        errs += _check_files(r.get("files"), w)
        if "cwe" in r and not (isinstance(r["cwe"], int) and 0 < r["cwe"] < 10000):
            errs.append(f"{w}: `cwe` is a number")
        if "confidence" in r and r["confidence"] not in ("HIGH", "LOW"):
            errs.append(f"{w}: `confidence` is HIGH or LOW")
        if "unless" in r:
            errs += _check_pattern(r["unless"], w + ".unless")
    for i, e in enumerate(entries):
        w = f"entries[{i}]"
        if not isinstance(e, dict):
            errs.append(f"{w}: must be an object")
            continue
        if e.get("kind") not in ENTRY_KINDS:
            errs.append(f"{w}: `kind` is one of {', '.join(ENTRY_KINDS)}")
        errs += _check_pattern(e.get("pattern"), w)
        errs += _check_files(e.get("files"), w)
        if not isinstance(e.get("handler"), str) or not re.fullmatch(r"\{\d\}", e["handler"]):
            errs.append(f"{w}: `handler` names a capture group, like \"{{2}}\"")
        if "detail" in e and not isinstance(e["detail"], str):
            errs.append(f"{w}: `detail` is a string with {{n}} placeholders")
    return errs


def _check_pattern(pat, where: str) -> list[str]:
    if not isinstance(pat, str) or not pat:
        return [f"{where}: `pattern` is a regular expression"]
    if len(pat) > MAX_PATTERN:
        return [f"{where}: pattern longer than {MAX_PATTERN} characters"]
    try:
        re.compile(pat)
    except re.error as e:
        return [f"{where}: bad pattern: {e}"]
    return []


def _check_files(files, where: str) -> list[str]:
    if not isinstance(files, list) or not files or not all(isinstance(x, str) and x for x in files):
        return [f"{where}: `files` is a list of glob patterns like \"**/settings*.py\""]
    return []


# ---------------------------------------------------------------------------- loading

def _read_pack(p: Path, source: str) -> tuple[dict | None, str | None]:
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return None, f"not readable as JSON ({type(e).__name__})"
    errs = validate(data)
    if errs:
        return None, "; ".join(errs[:4])
    data["source"] = source
    data["file"] = p.name
    return data, None


def load_all(repo: Path | None = None, builtin: bool = True,
             keep_inactive: bool = False) -> tuple[list[dict], list[tuple[str, str]]]:
    """All usable packs, built-in first, and the files that were skipped with why. Packs with `requires` that
    the repo does not meet are left out quietly (they are for another framework), or kept with
    `active: False` when `keep_inactive` is set (for `lantern packs`)."""
    places = []
    if builtin and BUILTIN_DIR.is_dir():
        places.append((BUILTIN_DIR, "builtin"))
    if repo is not None and (repo / PROJECT_DIR).is_dir():
        places.append((repo / PROJECT_DIR, "project"))
    if user_dir().is_dir():
        places.append((user_dir(), "user"))
    packs, problems, names = [], [], set()
    for d, source in places:
        for p in sorted(d.glob("*.json")):
            if source == "project" and not inside_repo(p, repo):
                continue
            pk, err = _read_pack(p, source)
            if err:
                problems.append((f"{source} pack {p.name}", err))
                continue
            if pk["pack"] in names:
                problems.append((f"{source} pack {p.name}", f"a pack called {pk['pack']} is already loaded"))
                continue
            pk["active"] = repo is None or _applies(pk, repo)
            if not pk["active"] and not keep_inactive:
                continue
            names.add(pk["pack"])
            packs.append(pk)
    return packs, problems


def _applies(pk: dict, repo: Path) -> bool:
    req = pk.get("requires") or {}
    for pat in req.get("files", []):
        if not any(_files(repo, [pat])):
            return False
    for word in req.get("text", []):
        if not any(word in _read(p) for p in _manifests(repo)):
            return False
    return True


def _manifests(repo: Path):
    for name in ("requirements.txt", "pyproject.toml", "Pipfile", "package.json", "setup.py", "setup.cfg", "go.mod",
                 "Gemfile", "composer.json", "Cargo.toml"):
        for p in _files(repo, [name, f"*/{name}"]):
            yield p


def _files(repo: Path, globs: list[str]):
    """Repo files matching any glob (`**/x.py`, `*.py`, `settings*.py`), skipping build and dependency folders."""
    pats = []
    for gl in globs:
        gl = gl.replace("\\", "/")
        pats.append(gl)
        if not gl.startswith("**/") and "/" not in gl:
            pats.append("**/" + gl)
    for p in repo.rglob("*"):
        if not p.is_file() or not inside_repo(p, repo):
            continue
        rel = p.relative_to(repo)
        if any(x in SKIP_DIRS for x in rel.parts[:-1]) or PROJECT_DIR in rel.parts[:-1]:
            continue
        rp = rel.as_posix()
        if any(fnmatch.fnmatchcase(rp, pat) or fnmatch.fnmatchcase(rp, pat.removeprefix("**/")) for pat in pats):
            yield p


def _read(p: Path) -> str:
    try:
        if p.stat().st_size > MAX_FILE:
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _lines(text: str):
    for i, line in enumerate(text.splitlines(), 1):
        yield i, line[:MAX_LINE]


# ---------------------------------------------------------------------------- rules -> findings

def _fid(*parts) -> str:
    import hashlib
    return hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).hexdigest()[:12]


def scan_packs(repo: Path, packs: list[dict]) -> tuple[list[dict], list[dict]]:
    """Findings from every pack rule, one per matching line, plus a tool row per pack for the report's About."""
    findings, tools = [], []
    for pk in packs:
        n = 0
        for r in pk.get("rules", []):
            rx = re.compile(r["pattern"])
            unless = re.compile(r["unless"]) if r.get("unless") else None
            conf = "HIGH" if pk["source"] == "builtin" and r.get("confidence") == "HIGH" else "LOW"
            for p in _files(repo, r["files"]):
                if p.suffix.lower() not in TEXT_EXTS and p.suffix:
                    continue
                rel = p.relative_to(repo).as_posix()
                for ln, line in _lines(_read(p)):
                    if not rx.search(line) or (unless and unless.search(line)):
                        continue
                    s = line.lstrip()
                    if s.startswith(("#", "//", "*", "/*", "<!--")):
                        continue
                    findings.append({"id": _fid("lp", r["id"], rel, ln), "tool": f"lantern-pack:{pk['pack']}", "rule": r["id"],
                                     "title": r["title"], "tool_severity": r["severity"], "tool_confidence": conf,
                                     "file": rel, "line": ln, "cwe": r.get("cwe"),
                                     "more_info": " ".join(x for x in (r.get("more"), r.get("fix") and "Fix: " + r["fix"]) if x) or None,
                                     "snippet": s[:300], "category": r.get("category", "code"), "pack": pk["pack"]})
                    n += 1
        tools.append({"tool": f"lantern-pack:{pk['pack']}", "status": f"ok ({pk['source']}, {n} finding(s))",
                      "version": str(pk.get("version", "-"))})
    return findings, tools


# ---------------------------------------------------------------------------- entries -> entry points

def _handler_nodes(g: Graph, handler: str, near_file: str) -> list[str]:
    """Graph nodes a handler name in a registration refers to: `views.index`, `ItemView.as_view`, `index`."""
    h = re.sub(r"\.as_view(\(\))?$|\(\)$", "", handler.strip())
    if not h:
        return []
    parts = h.split(".")
    cands = []
    for n in g.nodes.values():
        if n.kind not in ("callable", "class") or not n.file:
            continue
        q = n.qualname.split(".")
        if q[-len(parts):] == parts:
            cands.append(n)
    if len(cands) > 1:
        folder = near_file.rsplit("/", 1)[0] if "/" in near_file else ""
        same = [n for n in cands if (n.file.rsplit("/", 1)[0] if "/" in n.file else "") == folder]
        if same:
            cands = same
    out = []
    for n in cands:
        if n.kind == "class":   # class-based view: the methods that answer requests
            methods = [m for m in g.nodes.values() if m.parent == n.id and m.kind == "callable" and
                       m.name in ("dispatch", "get", "post", "put", "patch", "delete", "handle", "__call__")]
            out += [m.id for m in methods]
        else:
            out.append(n.id)
    return out


def apply_entries(g: Graph, repo: Path, packs: list[dict]) -> dict:
    """Mark the functions a pack's registration patterns point at as entry points. Existing entries are kept.
    Ambiguous handler names are counted, not guessed."""
    stats = {"added": 0, "ambiguous": 0, "unresolved": 0, "packs": [p["pack"] for p in packs]}
    for pk in packs:
        for e in pk.get("entries", []):
            rx = re.compile(e["pattern"])
            gi = int(e["handler"][1:-1])
            for p in _files(repo, e["files"]):
                rel = p.relative_to(repo).as_posix()
                for ln, line in _lines(_read(p)):
                    for m in rx.finditer(line):
                        if gi > (m.lastindex or 0) or not m.group(gi):
                            continue
                        detail = e.get("detail") or ""
                        for k in range(1, (m.lastindex or 0) + 1):
                            detail = detail.replace(f"{{{k}}}", m.group(k) or "")
                        detail = re.sub(r"/{2,}", "/", detail).strip() or None
                        ids = _handler_nodes(g, m.group(gi), rel)
                        if not ids:
                            stats["unresolved"] += 1
                            continue
                        if len({g.nodes[i].parent or i for i in ids}) > 1:
                            stats["ambiguous"] += 1
                            continue
                        for nid in ids:
                            n = g.nodes[nid]
                            if n.entry:
                                continue
                            n.entry = {"kind": e["kind"], "detail": detail, "via": f"pack:{pk['pack']}",
                                       "registered_at": f"{rel}:{ln}"}
                            stats["added"] += 1
    g.meta["packs"] = stats
    return stats
