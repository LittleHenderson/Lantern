"""Security stage: deterministic scanners find issues; the call graph ranks them by reachability.

Models never create or close findings. They only explain them later (see explain.py).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import deque
from pathlib import Path

from .graph import Graph
from .python_frontend import SKIP_DIRS

UNTRUSTED_ENTRY_KINDS = {"route", "cli", "main", "script"}

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-live-key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b")),
]
SECRET_EXTS = {".py", ".env", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".txt", ".sh",
               ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html",
               ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".php", ".tf", ".properties", ".xml"}
SECRET_SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock", "uv.lock"}


def _fid(*parts) -> str:
    return hashlib.sha1("|".join(map(str, parts)).encode(), usedforsecurity=False).hexdigest()[:12]


# ---------------------------------------------------------------------------- scanners

def run_bandit(repo: Path) -> tuple[list[dict], dict]:
    excl = ",".join(str(repo / d) for d in SKIP_DIRS if (repo / d).exists())
    cmd = [sys.executable, "-m", "bandit", "-r", str(repo), "-f", "json", "-q", "--exit-zero"]
    if excl:
        cmd += ["-x", excl]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return [], {"tool": "bandit", "status": f"error: {exc}"}
    out = []
    for r in data.get("results", []):
        rel = str(Path(r["filename"]).resolve().relative_to(repo))
        out.append({
            "id": _fid("bandit", r["test_id"], rel, r["line_number"]),
            "tool": "bandit", "rule": r["test_id"], "title": r["issue_text"],
            "tool_severity": r["issue_severity"], "tool_confidence": r["issue_confidence"],
            "file": rel, "line": r["line_number"],
            "cwe": (r.get("issue_cwe") or {}).get("id"), "more_info": r.get("more_info"),
            "snippet": (r.get("code") or "").strip()[:400], "category": "code",
        })
    version = _tool_version([sys.executable, "-m", "bandit", "--version"])
    return out, {"tool": "bandit", "status": "ok", "version": version}


def run_pip_audit(repo: Path) -> tuple[list[dict], dict]:
    reqs = sorted(p for p in repo.glob("requirements*.txt") if p.is_file())
    if not reqs:
        return [], {"tool": "pip-audit", "status": "skipped: no requirements*.txt (pyproject support is Phase 1)"}
    if not shutil.which("pip-audit"):
        return [], {"tool": "pip-audit", "status": "skipped: not installed"}
    out = []
    for req in reqs:
        cmd = ["pip-audit", "-r", str(req), "-f", "json", "--progress-spinner", "off",
               "--no-deps", "--disable-pip"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            data = json.loads(proc.stdout or "{}")
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            return out, {"tool": "pip-audit", "status": f"error: {exc}"}
        for dep in data.get("dependencies", []):
            for v in dep.get("vulns", []):
                out.append({
                    "id": _fid("pip-audit", dep["name"], v["id"]),
                    "tool": "pip-audit", "rule": v["id"],
                    "title": f"{dep['name']} {dep.get('version', '')} has known vulnerability {v['id']}",
                    "tool_severity": "HIGH", "tool_confidence": "HIGH",
                    "file": str(req.relative_to(repo)), "line": None,
                    "more_info": f"Fixed in: {', '.join(v.get('fix_versions', [])) or 'no fix yet'}",
                    "snippet": (v.get("description") or "")[:400], "category": "dependency",
                    "package": dep["name"],
                })
    return out, {"tool": "pip-audit", "status": "ok", "files": [str(r.relative_to(repo)) for r in reqs]}


def run_secrets(repo: Path) -> tuple[list[dict], dict]:
    """gitleaks when installed; otherwise a small built-in pattern scan."""
    if shutil.which("gitleaks"):
        try:
            proc = subprocess.run(
                ["gitleaks", "detect", "--no-git", "-s", str(repo), "-f", "json", "-r", "/dev/stdout",
                 "--exit-code", "0"], capture_output=True, text=True, timeout=300)
            rows = json.loads(proc.stdout or "[]")
            out = [{
                "id": _fid("gitleaks", r["RuleID"], r["File"], r["StartLine"]),
                "tool": "gitleaks", "rule": r["RuleID"], "title": f"Possible secret: {r['Description']}",
                "tool_severity": "HIGH", "tool_confidence": "MEDIUM",
                "file": str(Path(r["File"]).resolve().relative_to(repo)), "line": r["StartLine"],
                "snippet": "[redacted]", "category": "secret",
            } for r in rows]
            return out, {"tool": "gitleaks", "status": "ok"}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, ValueError):
            pass  # fall through to the built-in patterns below
    out = []
    for p in repo.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(repo).parts[:-1]):
            continue
        if p.suffix not in SECRET_EXTS and not p.name.startswith(".env"):
            continue
        if p.name in SECRET_SKIP_FILES or p.name.endswith((".min.js", ".map")):
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for rule, rx in SECRET_PATTERNS:
                if rx.search(line):
                    rel = str(p.relative_to(repo))
                    out.append({
                        "id": _fid("secrets", rule, rel, i), "tool": "lantern-secrets", "rule": rule,
                        "title": f"Possible secret ({rule})", "tool_severity": "HIGH",
                        "tool_confidence": "MEDIUM", "file": rel, "line": i,
                        "snippet": "[redacted]", "category": "secret",
                    })
    return out, {"tool": "lantern-secrets", "status": "ok (built-in patterns; install gitleaks for full coverage)"}


def _tool_version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout
        m = re.search(r"\d+\.\d+(\.\d+)?", out)
        return m.group(0) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------------------- graph link

def _node_at(g: Graph, file: str | None, line: int | None) -> str | None:
    if not file:
        return None
    best, best_span = None, None
    for n in g.nodes.values():
        if n.file != file or n.start_line is None:
            continue
        if line is None:
            if n.kind == "module":
                return n.id
            continue
        if n.start_line <= line <= (n.end_line or n.start_line):
            span = (n.end_line or n.start_line) - n.start_line
            if best_span is None or span < best_span:
                best, best_span = n.id, span
    return best


def reachability(g: Graph, include_tests: bool = False, kinds: set[str] | None = None) -> dict[str, dict]:
    """Multi-source BFS from entry points. Returns node id -> {entry, kind, path}."""
    adj: dict[str, list[str]] = {}
    for e in g.call_edges():
        adj.setdefault(e.src, []).append(e.dst)
    seen: dict[str, dict] = {}
    q: deque[str] = deque()
    entries = [n for n in g.entry_points() if (include_tests or n.entry["kind"] != "test")
               and (kinds is None or n.entry["kind"] in kinds)]
    # untrusted-input entries first so their paths win ties
    entries.sort(key=lambda n: 0 if n.entry["kind"] in UNTRUSTED_ENTRY_KINDS else 1)
    for n in entries:
        if n.id not in seen:
            seen[n.id] = {"entry": n.id, "kind": n.entry["kind"], "prev": None}
            q.append(n.id)
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen[nxt] = {"entry": seen[cur]["entry"], "kind": seen[cur]["kind"], "prev": cur}
                q.append(nxt)
    out = {}
    for nid, info in seen.items():
        path, cur = [], nid
        while cur is not None:
            path.append(cur)
            cur = seen[cur]["prev"]
        out[nid] = {"entry": info["entry"], "kind": info["kind"], "path": list(reversed(path))}
    return out


def rank(f: dict) -> str:
    if f.get("fixed_rank"):
        return f["fixed_rank"]
    sev = f["tool_severity"]
    reach = f.get("reachable")
    untrusted = reach and reach["kind"] in UNTRUSTED_ENTRY_KINDS
    if f["category"] == "secret":
        return "critical"
    if f["category"] == "dependency":
        return "high"
    if sev == "HIGH" and untrusted:
        return "critical"
    if (sev == "HIGH" and reach) or (sev == "MEDIUM" and untrusted):
        return "high"
    if (sev == "MEDIUM" and reach) or sev == "HIGH":
        return "medium"
    return "low"


RANK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ACCEPTED_FILE = "lantern-accepted.json"


def load_accepted(repo: Path) -> dict[str, dict]:
    """Accepted risks live in the repo (committed), each with the builder's written reason."""
    p = repo / ACCEPTED_FILE
    try:
        rows = json.loads(p.read_text()).get("accepted", []) if p.exists() else []
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}
    return {r["id"]: r for r in rows if isinstance(r, dict) and r.get("id") and r.get("reason")}


def save_accepted(repo: Path, accepted: dict[str, dict]) -> Path:
    p = repo / ACCEPTED_FILE
    rows = sorted(accepted.values(), key=lambda r: r["id"])
    p.write_text(json.dumps({"about": "Security findings the builder reviewed and accepted, with reasons. "
                                      "Managed by `lantern accept`.", "accepted": rows}, indent=1) + "\n")
    return p


def scan(g: Graph) -> dict:
    repo = Path(g.repo_root)
    findings, tools = [], []
    for fn in (run_bandit, run_pip_audit, run_secrets):
        f, info = fn(repo)
        findings += f
        tools.append(info)
    from .websec import scan_web
    wf, wt = scan_web(g)
    findings += wf
    tools += wt
    accepted = load_accepted(repo)
    reach = reachability(g)
    ui_reach = reachability(g, kinds={"page", "main"})
    test_reach = reachability(g, include_tests=True)
    from .js_frontend import TEST_RE as JS_TEST_RE
    from .python_frontend import TEST_FILE_RE
    for f in findings:
        f["in_tests"] = bool(f["file"] and (TEST_FILE_RE.search(f["file"]) or JS_TEST_RE.search(f["file"])))
        f["node"] = _node_at(g, f["file"], f["line"])
        r = reach.get(f["node"]) if f["node"] else None
        f["reachable"] = r
        f["reachable_from_tests_only"] = bool(not r and f["node"] in test_reach)
        u = ui_reach.get(f["node"]) if f["node"] else None
        f["ui_path"] = u["path"] if u else None
        f["rank"] = "low" if f["in_tests"] and f["category"] == "code" else rank(f)
        acc = accepted.get(f["id"])
        f["status"] = "accepted" if acc else "open"
        if acc:
            f["accepted"] = {k: acc.get(k) for k in ("reason", "by", "date")}
    findings.sort(key=lambda f: (f["in_tests"], RANK_ORDER[f["rank"]], f["file"] or "", f["line"] or 0))
    live = [f for f in findings if not f["in_tests"] and f["status"] == "open"]
    counts = {k: sum(1 for f in live if f["rank"] == k) for k in RANK_ORDER}
    counts["in_tests"] = sum(1 for f in findings if f["in_tests"])
    counts["accepted"] = sum(1 for f in findings if f["status"] == "accepted")
    return {"findings": findings, "tools": tools, "counts": counts,
            "reachable_nodes": len(reach), "total_callables": sum(1 for n in g.nodes.values() if n.kind == "callable")}
