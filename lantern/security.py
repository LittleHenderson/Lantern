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
from .python_frontend import SKIP_DIRS, inside_repo

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
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
        data = json.loads(proc.stdout or "{}")
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        return [], {"tool": "bandit", "status": f"error: {exc}"}
    out = []
    for r in data.get("results", []):
        rel = Path(r["filename"]).resolve().relative_to(repo).as_posix()
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


def run_secrets(repo: Path) -> tuple[list[dict], dict]:
    """gitleaks when installed; otherwise a small built-in pattern scan."""
    if shutil.which("gitleaks"):
        try:
            proc = subprocess.run(
                ["gitleaks", "detect", "--no-git", "-s", str(repo), "-f", "json", "-r", "/dev/stdout",
                 "--exit-code", "0"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
            rows = json.loads(proc.stdout or "[]")
            out = [{
                "id": _fid("gitleaks", r["RuleID"], r["File"], r["StartLine"]),
                "tool": "gitleaks", "rule": r["RuleID"], "title": f"Possible secret: {r['Description']}",
                "tool_severity": "HIGH", "tool_confidence": "MEDIUM",
                "file": Path(r["File"]).resolve().relative_to(repo).as_posix(), "line": r["StartLine"],
                "snippet": "[redacted]", "category": "secret",
            } for r in rows]
            return out, {"tool": "gitleaks", "status": "ok"}
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, KeyError, ValueError):
            pass  # fall through to the built-in patterns below
    out = []
    for p in repo.rglob("*"):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(repo).parts[:-1]) \
                or not inside_repo(p, repo):
            continue
        if p.suffix not in SECRET_EXTS and not p.name.startswith(".env"):
            continue
        if p.name in SECRET_SKIP_FILES or p.name.endswith((".min.js", ".map")):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for rule, rx in SECRET_PATTERNS:
                if rx.search(line):
                    rel = p.relative_to(repo).as_posix()
                    out.append({
                        "id": _fid("secrets", rule, rel, i), "tool": "lantern-secrets", "rule": rule,
                        "title": f"Possible secret ({rule})", "tool_severity": "HIGH",
                        "tool_confidence": "MEDIUM", "file": rel, "line": i,
                        "snippet": "[redacted]", "category": "secret",
                    })
    return out, {"tool": "lantern-secrets", "status": "ok (built-in patterns; install gitleaks for full coverage)"}


def _tool_version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30).stdout
        m = re.search(r"\d+\.\d+(\.\d+)?", out)
        return m.group(0) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------------------- graph link

REQUEST_DATA = re.compile(r"\b(request|req)\.(args|form|json|body|query|params|values|files|data|cookies|headers|"
                          r"get_json|path_params|query_params)\b|\bsearchParams\b|\bformData\b|\bsys\.argv\b|"
                          r"\binput\(|\bevent\[|\bctx\.(query|params|request)\b")


def _input_on_line(g: Graph, f: dict, cache: dict[str, list[str]]) -> dict | False:
    """Does the flagged line use something a caller controls: one of the function's parameters, or request data?
    Local and one line only (no data-flow across functions), so it can say yes for a parameter that is in fact
    always a constant, and it says no for input that arrives through another variable first."""
    n = g.nodes.get(f.get("node") or "")
    if not n or not f.get("line"):
        return False
    if f["file"] not in cache:
        try:
            cache[f["file"]] = (Path(g.repo_root) / f["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[f["file"]] = []
    src = cache[f["file"]]
    if not 0 < f["line"] <= len(src):
        return False
    # bandit points at the statement's first line; take the statement's continuation lines too
    text = " ".join(src[f["line"] - 1:min(len(src), f["line"] + 3)])
    m = REQUEST_DATA.search(text)
    if m:
        return {"via": f"request data `{m.group(0)}`"}
    sig = n.signature or ""
    params = re.findall(r"[(,]\s*\*{0,2}([A-Za-z_]\w*)", sig[sig.find("("):] if "(" in sig else "")
    for name in params:
        if name not in ("self", "cls") and re.search(rf"(?<![\w.]){name}\b", text):
            return {"via": f"parameter `{name}`"}
    return False


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
    if f["category"] == "dependency":   # npm says how bad; pip-audit doesn't, so those stay high
        return {"moderate": "medium", "low": "low", "info": "low"}.get(str(f.get("dep_severity")), "high")
    if sev == "HIGH" and untrusted and f.get("input") is not False:
        return "critical"   # spec 9.3: high severity and touched by untrusted input (False: the line uses none)
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
        rows = json.loads(p.read_text(encoding="utf-8")).get("accepted", []) if p.exists() else []
    except (OSError, json.JSONDecodeError, AttributeError):
        return {}
    return {r["id"]: r for r in rows if isinstance(r, dict) and r.get("id") and reason_ok(r.get("reason"))}


def reason_ok(reason) -> bool:
    """A real written reason: at least 10 letters/digits across two or more words, not one repeated character.
    Applies to hand-edited `lantern-accepted.json` too, so "x" can't silence --fail-on."""
    if not isinstance(reason, str):
        return False
    words = re.findall(r"[^\W_]{2,}", reason)
    chars = "".join(words)
    return len(words) >= 2 and len(chars) >= 10 and len(set(chars.lower())) >= 5


def save_accepted(repo: Path, accepted: dict[str, dict]) -> Path:
    p = repo / ACCEPTED_FILE
    rows = sorted(accepted.values(), key=lambda r: r["id"])
    p.write_text(json.dumps({"about": "Security findings the builder reviewed and accepted, with reasons. "
                                      "Managed by `lantern accept`.", "accepted": rows}, indent=1) + "\n", encoding="utf-8")
    return p


ID_VERSION = 2


def stable_ids(repo: Path, findings: list[dict]) -> None:
    """Give each finding an id that survives moving its code: tool, rule, file, and the flagged line's text with
    spaces removed, plus a counter for identical lines in one file. Lines added above a finding don't change it,
    so "fixed" means the flagged code is really gone (or changed). Findings without a line keep the scanner's id."""
    lines: dict[str, list[str]] = {}
    seen: dict[str, int] = {}
    for f in sorted(findings, key=lambda f: (f.get("file") or "", f.get("line") or 0, f.get("rule") or "")):
        if not f.get("file") or not f.get("line"):
            continue
        if f["file"] not in lines:
            try:
                lines[f["file"]] = (repo / f["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines[f["file"]] = []
        src = lines[f["file"]]
        text = re.sub(r"\s+", "", src[f["line"] - 1]) if 0 < f["line"] <= len(src) else f"line{f['line']}"
        key = "|".join(map(str, (f.get("tool"), f.get("rule"), f["file"], text)))
        seen[key] = seen.get(key, 0) + 1
        f["id"] = _fid(key, seen[key])


def scan(g: Graph, offline: bool | None = None) -> dict:
    """All scanners. `offline` skips the dependency audits, the only steps that use the network
    (None: follow LANTERN_OFFLINE)."""
    repo = Path(g.repo_root)
    findings, tools = [], []
    from .depaudit import run_npm_audit, run_pip_audit
    for fn in (run_bandit, lambda r: run_pip_audit(r, offline), lambda r: run_npm_audit(r, offline), run_secrets):
        f, info = fn(repo)
        findings += f
        tools.append(info)
    from .websec import scan_web
    wf, wt = scan_web(g)
    findings += wf
    tools += wt
    stable_ids(repo, findings)
    accepted = load_accepted(repo)
    reach = reachability(g)
    ui_reach = reachability(g, kinds={"page", "main"})
    test_reach = reachability(g, include_tests=True)
    from .js_frontend import TEST_RE as JS_TEST_RE
    from .python_frontend import TEST_FILE_RE
    lines_cache: dict[str, list[str]] = {}
    for f in findings:
        f["in_tests"] = bool(f["file"] and (TEST_FILE_RE.search(f["file"]) or JS_TEST_RE.search(f["file"])))
        f["node"] = _node_at(g, f["file"], f["line"])
        r = reach.get(f["node"]) if f["node"] else None
        f["reachable"] = r
        f["reachable_from_tests_only"] = bool(not r and f["node"] in test_reach)
        u = ui_reach.get(f["node"]) if f["node"] else None
        f["ui_path"] = u["path"] if u else None
        f["input"] = _input_on_line(g, f, lines_cache) if f["category"] == "code" and r and \
            r["kind"] in UNTRUSTED_ENTRY_KINDS else None
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
    return {"findings": findings, "tools": tools, "counts": counts, "id_version": ID_VERSION,
            "reachable_nodes": len(reach), "total_callables": sum(1 for n in g.nodes.values() if n.kind == "callable")}
