"""Fix this for me: an optional coding agent of the person's choice fixes one finding, and Lantern checks the fix
(directive: user first, step 6).

Facts come from tools, words from models: the agent writes the change, and Lantern's own analysis, not the agent,
says whether the finding is gone and whether anything new appeared. Nothing reaches the person's project until they
press Apply.

- Off until the person picks an agent in Settings. Only the agents listed in `AGENTS` can be picked, each run as a
  fixed command (an argument list, never a shell line), so nothing on a page can make Lantern run something else.
- The agent works on a copy of the project in a temporary folder, never on the project itself.
- Lantern then analyzes the copy, compares it with the project's own results, and shows the verdict and the
  changed files. Apply copies only those files back, and only if the person has not changed them meanwhile.
- The agent runs as the person, with their own sign-in to that agent; Lantern passes it no Lantern token or key.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

# id -> (name, the program to look for, how its command is built). The prompt is always one argument.
AGENTS = {
    "claude": ("Claude Code", "claude", lambda prompt: ["claude", "-p", prompt, "--permission-mode", "acceptEdits"]),
    "codex": ("Codex", "codex", lambda prompt: ["codex", "exec", "--sandbox", "workspace-write", prompt]),
    "aider": ("Aider", "aider", lambda prompt: ["aider", "--yes-always", "--no-auto-commits", "--no-gitignore",
                                                "--message", prompt]),
}
SKIP_DIRS = {".git", ".lantern", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
             ".next", "dist", "build", ".gradle", "target", ".dart_tool", "Pods", ".tox"}
MAX_FILES, MAX_BYTES = 20_000, 300 << 20      # a copy bigger than this is refused, not made
AGENT_MINUTES = 15
DIFF_LINES = 400                               # per file, in what the page shows
FIXES_DIR = "lantern-fixes"


def available() -> list[dict]:
    """The agents Lantern knows, and whether each one's program is on this computer."""
    return [{"id": k, "name": v[0], "found": shutil.which(v[1]) is not None} for k, v in AGENTS.items()]


def _work(work_root: Path | None) -> Path:
    """Fixes live under LANTERN_HOME/fixes (only this person can read it), never in a shared temp folder."""
    if work_root is not None:
        return Path(work_root)
    from .server import home_dir
    return home_dir() / "fixes"


def _files(root: Path) -> dict[str, str]:
    """relative path -> sha256 for every file Lantern copies (the same walk for the project and the copy)."""
    got: dict[str, str] = {}
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink() or not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            data = p.read_bytes()
            total += len(data)
            if len(got) >= MAX_FILES or total > MAX_BYTES:
                raise ValueError("This project is too big to copy for a fix. Leave out build output and dependencies.")
            got[rel] = hashlib.sha256(data).hexdigest()
    return got


def _prompt(f: dict) -> str:
    where = f"{f.get('file') or ''}{':' + str(f['line']) if f.get('line') else ''}"
    reach = " A visitor can reach it from the app." if f.get("ui_path") or f.get("reachable") else ""
    via = f" It uses outside input ({f['input']['via']})." if isinstance(f.get("input"), dict) and f["input"].get("via") else ""
    return (f"Fix this security problem in this project, with the smallest change that fixes it: {f.get('title')} "
            f"({f.get('rule')}) at {where}.{reach}{via}\n"
            "Change only the files needed. Keep the app's behavior for normal use. Do not add dependencies, do not "
            "touch tests to make them pass, and do not commit. When you are done, stop.")


def _finding(out: Path, fid: str) -> dict:
    try:
        sec = json.loads((out / "security.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raise ValueError("Analyze the project first.") from None
    f = next((x for x in sec.get("findings") or [] if isinstance(x, dict) and x.get("id") == fid), None)
    if not f or f.get("status") != "open" or f.get("in_tests"):
        raise ValueError("That finding is not open any more. Analyze the project again.")
    return f


def _diff_text(a: Path | None, b: Path | None, rel: str) -> str:
    def lines(p):
        if p is None or not p.exists():
            return []
        try:
            return p.read_text(encoding="utf-8").splitlines(keepends=True)
        except UnicodeDecodeError:
            return None
    la, lb = lines(a), lines(b)
    if la is None or lb is None:
        return "(a binary file changed)"
    d = list(difflib.unified_diff(la, lb, f"a/{rel}", f"b/{rel}"))
    return "".join(d[:DIFF_LINES]) + (f"\n… {len(d) - DIFF_LINES} more lines\n" if len(d) > DIFF_LINES else "")


def run_fix(repo: Path, out: Path, fid: str, agent: str, privacy: str, log, *, runner=subprocess.run,
            work_root: Path | None = None) -> dict:
    """Copy the project, let the agent fix finding `fid` in the copy, analyze the copy, and say what changed.
    Returns the verdict and the changed files; the copy is kept for `apply_fix` or `discard_fix`."""
    from . import pipeline
    from .mcp_server import _diff, _snapshot
    if agent not in AGENTS:
        raise ValueError("Pick a coding agent in Settings first.")
    name, prog, build = AGENTS[agent]
    if shutil.which(prog) is None and runner is subprocess.run:
        raise ValueError(f"{name} is not installed on this computer, or Lantern can't find it.")
    f = _finding(out, fid)
    before_files = _files(repo)
    base = _work(work_root) / FIXES_DIR
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    fix_id = f"{fid[:24]}-{int(time.time())}".replace("/", "-")
    copy = base / fix_id / repo.name
    log(f"copying {len(before_files)} files to a scratch folder (your project is not touched)")
    for rel in before_files:
        dst = copy / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / rel, dst)
    log(f"asking {name} to fix it there")
    env = {k: v for k, v in os.environ.items() if not k.startswith("LANTERN")}
    try:
        res = runner(build(_prompt(f)), cwd=str(copy), env=env, stdin=subprocess.DEVNULL, capture_output=True,
                     text=True, encoding="utf-8", errors="replace", timeout=AGENT_MINUTES * 60)
    except subprocess.TimeoutExpired:
        raise ValueError(f"{name} did not finish within {AGENT_MINUTES} minutes. Nothing in your project changed.") from None
    except FileNotFoundError:
        raise ValueError(f"{name} is not installed on this computer, or Lantern can't find it.") from None
    for ln in (res.stdout or "").splitlines()[-12:]:
        log(f"{agent}: {ln[:200]}")
    after_files = _files(copy)
    changed = sorted(k for k in set(before_files) | set(after_files) if before_files.get(k) != after_files.get(k))
    if not changed:
        discard_fix(base / fix_id)
        return {"fix": None, "status": "no_change", "agent": name, "returncode": res.returncode,
                "verdict": f"{name} didn't change any files. Nothing in your project changed.", "files": []}
    log(f"{name} changed {len(changed)} file(s); Lantern is checking the copy")
    cout = pipeline.out_dir(copy)
    pipeline.analyze(copy, cout, privacy, log=lambda ln: log("check: " + str(ln)), offline=True)
    was, now = _snapshot(out), _snapshot(cout)
    d = _diff(was, now)
    target = was.get(fid) or f
    worse = [x for x in d["new"] if x.get("rank") in ("critical", "high")]
    if fid in now or any(x["rule"] == target.get("rule") and x.get("file") == target.get("file") for x in d["new"]):
        status, verdict = "not_fixed", "Lantern still finds the problem in the changed copy. Don't apply this one."
    elif worse:
        status, verdict = "fixed_with_new", (f"The problem is gone, but the change adds {len(worse)} new serious "
                                             f"finding{'s' if len(worse) != 1 else ''}. Look before you apply it.")
    else:
        status, verdict = "fixed", "Fixed: Lantern no longer finds the problem, and nothing new and serious appeared."
    files = [{"path": rel, "change": "added" if rel not in before_files else "deleted" if rel not in after_files else "changed",
              "diff": _diff_text(repo / rel if rel in before_files else None, copy / rel if rel in after_files else None, rel)}
             for rel in changed]
    manifest = {"repo": str(repo), "finding": fid, "agent": agent, "status": status,
                "before": {rel: before_files.get(rel) for rel in changed},
                "after": {rel: after_files.get(rel) for rel in changed}}
    (base / fix_id / "fix.json").write_text(json.dumps(manifest), encoding="utf-8")
    return {"fix": fix_id, "status": status, "verdict": verdict, "agent": name, "returncode": res.returncode,
            "files": files, "new": [{k: x.get(k) for k in ("rank", "title", "file", "line")} for x in d["new"]][:10],
            "fixed": len(d["fixed"])}


def _fix_dir(fix_id: str, work_root: Path | None) -> Path:
    base = (_work(work_root) / FIXES_DIR).resolve()
    if not isinstance(fix_id, str) or not fix_id or "/" in fix_id or "\\" in fix_id or fix_id.startswith("."):
        raise ValueError("unknown fix")
    d = (base / fix_id).resolve()
    if d.parent != base or not (d / "fix.json").is_file():
        raise ValueError("That fix is gone. Ask the agent again.")
    return d


def apply_fix(repo: Path, fix_id: str, *, work_root: Path | None = None) -> dict:
    """Copy a checked fix into the project: only its changed files, and only if none of them changed meanwhile."""
    d = _fix_dir(fix_id, work_root)
    m = json.loads((d / "fix.json").read_text(encoding="utf-8"))
    if Path(m["repo"]).resolve() != repo.resolve():
        raise ValueError("That fix belongs to another project.")
    copy = d / repo.name
    for rel, h in m["before"].items():
        p = repo / rel
        now = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
        if now != h:
            raise ValueError(f"{rel} changed since the agent made its copy, so Lantern won't overwrite it. "
                             "Ask the agent again.")
    for rel, h in m["after"].items():
        src, dst = copy / rel, repo / rel
        if ".." in Path(rel).parts or Path(rel).is_absolute() or not dst.resolve().is_relative_to(repo.resolve()):
            raise ValueError("unsafe path")
        if h is None:
            dst.unlink(missing_ok=True)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
    discard_fix(d)
    return {"applied": sorted(m["after"]), "finding": m["finding"]}


def discard_fix(d_or_id, *, work_root: Path | None = None) -> None:
    d = d_or_id if isinstance(d_or_id, Path) else _fix_dir(d_or_id, work_root)
    shutil.rmtree(d, ignore_errors=True)
