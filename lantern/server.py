"""`lantern serve`: the local app. One command, a browser tab, nothing leaves the machine.

Serves the Home screen (projects, scores, runs), each project's Atlas report with live actions
(explain a function, accept a risk, write a starter file), the Evidence Report, and Settings
(model and key). Standard library only.

Safety model for a local server:
  * Binds to 127.0.0.1 by default.
  * Every request needs the session token: from the link printed at start (?token=...), then a
    SameSite=Strict HttpOnly cookie. Write requests also need it in the X-Lantern-Token header, which
    a cross-site page can't send without a CORS preflight this server never approves.
  * The Host header must name this server, which blocks DNS-rebinding attacks.
  * API keys stay in memory unless the user ticks "remember", then in ~/.lantern/keys.json (mode 0600).
"""

from __future__ import annotations

import hmac
import html
import json
import os
import re
import secrets
import shlex
import threading
import time
import traceback
import uuid
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, learn, pipeline, remote, usage
from .packs import PACK_NAME
from .providers import DEFAULT_MODEL_NAME, DEFAULT_PROVIDER, PRESETS
from .readiness import SHAPES

VIEWER = Path(__file__).parent / "viewer"
LOCAL_PROVIDERS = {"ollama", "lmstudio"}


def home_dir() -> Path:
    d = Path(os.environ.get("LANTERN_HOME") or Path.home() / ".lantern")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _pid(path: Path) -> str:
    import hashlib
    return hashlib.sha256(str(path).encode()).hexdigest()[:10]


class FileLock:
    """A lock held across threads and processes: two `lantern serve` sharing one LANTERN_HOME (or a server and a
    `lantern learn`) each read-modify-write projects.json, and an in-process lock alone let one overwrite the other's
    additions. The OS lock is on a separate file (`store.lock`), so the data files can still be replaced atomically."""

    def __init__(self, path: Path):
        self.path = path
        self.local = threading.Lock()
        self.fd: int | None = None

    def __enter__(self):
        self.local.acquire()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                if os.name == "nt":
                    import msvcrt
                    while True:   # LK_NBLCK fails at once when another process holds it; LK_LOCK gives up after 10 s
                        try:
                            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                            break
                        except OSError:
                            time.sleep(0.02)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
            except BaseException:
                os.close(fd)
                raise
            self.fd = fd
        except BaseException:
            self.local.release()
            raise
        return self

    def __exit__(self, *exc):
        fd, self.fd = self.fd, None
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
            self.local.release()


class Store:
    """Projects, settings, and remembered keys under LANTERN_HOME (default ~/.lantern)."""

    def __init__(self, root: Path):
        self.root = root
        self.lock = FileLock(root / "store.lock")
        self.session_keys: dict[str, str] = {}

    def _read(self, name, default):
        p = self.root / name
        try:
            return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default
        except (OSError, json.JSONDecodeError):
            return default

    def _write(self, name, data, private=False):
        """Write to a temporary file of this call's own (a shared `projects.tmp` let two writers interleave), then
        replace the file in one step. Callers hold `self.lock`."""
        import tempfile
        p = self.root / name
        self.root.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=f".{p.stem}.", suffix=".tmp")   # mode 0600
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(data, indent=1))
            if not private:
                os.chmod(tmp, 0o644)
            for attempt in range(50):   # Windows refuses to replace a file another process is reading at that moment
                try:
                    os.replace(tmp, p)
                    break
                except PermissionError:
                    if attempt == 49:
                        raise
                    time.sleep(0.02)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # projects
    def projects(self) -> list[dict]:
        return self._read("projects.json", [])

    def add_project(self, path: Path) -> dict:
        path = path.resolve()
        with self.lock:
            ps = self.projects()
            for p in ps:
                if p["path"] == str(path):
                    return p
            p = {"id": _pid(path), "path": str(path), "name": path.name or str(path),
                 "added": time.strftime("%Y-%m-%d %H:%M")}
            ps.append(p)
            self._write("projects.json", ps)
            return p

    def remove_project(self, pid: str) -> None:
        with self.lock:
            self._write("projects.json", [p for p in self.projects() if p["id"] != pid])

    def project(self, pid: str) -> dict | None:
        return next((p for p in self.projects() if p["id"] == pid), None)

    # settings and keys
    def settings(self) -> dict:
        return {"provider": DEFAULT_PROVIDER, "model": DEFAULT_MODEL_NAME, "base_url": "", "privacy": "full",
                "share_usage": False, "view_mode": "simple", "backdrop": "subtle", **self._read("settings.json", {})}

    def save_settings(self, s: dict) -> None:
        keep = {k: s.get(k) for k in ("provider", "model", "base_url", "privacy")}
        keep["share_usage"] = bool(s.get("share_usage"))
        keep["view_mode"] = "advanced" if s.get("view_mode") == "advanced" else "simple"
        keep["backdrop"] = s.get("backdrop") if s.get("backdrop") in ("off", "subtle", "bold") else "subtle"
        pk = s.get("packs") if isinstance(s.get("packs"), dict) else {}
        names = [n for n in pk.get("disabled") or [] if isinstance(n, str) and PACK_NAME.match(n)]
        if names or pk.get("changed_at"):
            keep["packs"] = {"disabled": sorted(set(names))[:100],
                             "changed_at": pk.get("changed_at") if isinstance(pk.get("changed_at"), (int, float)) else None}
        with self.lock:
            self._write("settings.json", keep)
        if keep["share_usage"]:
            usage.install_id()

    def confirmed_tests(self, pid: str) -> list[str]:
        d = self._read("test-confirmations.json", {})
        v = d.get(pid) if isinstance(d, dict) else None
        return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []

    def confirm_test(self, pid: str, command: str) -> None:
        with self.lock:
            d = self._read("test-confirmations.json", {})
            d = d if isinstance(d, dict) else {}
            have = [x for x in (d.get(pid) or []) if isinstance(x, str)]
            if command not in have:
                d[pid] = (have + [command])[-20:]
                self._write("test-confirmations.json", d)

    def key_for(self, provider: str) -> str | None:
        env = (PRESETS.get(provider) or (None, None, "LANTERN_API_KEY"))[2]
        return (self.session_keys.get(provider) or self._read("keys.json", {}).get(provider)
                or (os.environ.get(env) if env else None))

    def key_source(self, provider: str) -> str | None:
        env = (PRESETS.get(provider) or (None, None, "LANTERN_API_KEY"))[2]
        if self.session_keys.get(provider):
            return "this session"
        if self._read("keys.json", {}).get(provider):
            return "remembered on this computer"
        if env and os.environ.get(env):
            return f"environment variable {env}"
        return None

    def set_key(self, provider: str, key: str, remember: bool) -> None:
        with self.lock:
            keys = self._read("keys.json", {})
            if remember:
                keys[provider] = key
                self.session_keys.pop(provider, None)
            else:
                self.session_keys[provider] = key
                keys.pop(provider, None)
            self._write("keys.json", keys, private=True)

    def forget_key(self, provider: str) -> None:
        with self.lock:
            self.session_keys.pop(provider, None)
            keys = self._read("keys.json", {})
            keys.pop(provider, None)
            self._write("keys.json", keys, private=True)


class Jobs:
    def __init__(self):
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()

    def busy(self, pid: str) -> dict | None:
        return next((j for j in self.jobs.values() if j["project"] == pid and j["status"] == "running"), None)

    def start(self, pid: str, kind: str, fn) -> dict:
        with self.lock:
            if self.busy(pid):
                raise RuntimeError("a run is already in progress for this project")
            job = {"id": uuid.uuid4().hex[:12], "project": pid, "kind": kind, "status": "running",
                   "log": [], "result": None, "error": None, "started": time.time()}
            self.jobs[job["id"]] = job

        def log(line):
            job["log"].append(str(line))

        def work():
            try:
                job["result"] = fn(log)
                job["status"] = "done"
            except Exception as exc:  # noqa: BLE001 - reported to the user, not swallowed
                job["status"] = "error"
                job["error"] = f"{type(exc).__name__}: {exc}"
                log(traceback.format_exc(limit=3))
            job["finished"] = time.time()

        threading.Thread(target=work, daemon=True).start()
        return job


class App:
    def __init__(self, store: Store, token: str, port: int):
        self.store, self.token, self.port = store, token, port
        self.jobs = Jobs()

    def out(self, p: dict) -> Path:
        return pipeline.out_dir(Path(p["path"]))

    def summary(self, p: dict) -> dict:
        out = Path(p["path"]) / ".lantern"
        rd = _load(out / "readiness.json") or {}
        sec = _load(out / "security.json") or {}
        run = _load(out / "run.json") or {}
        ex = _load(out / "explanations.json") or {}
        busy = self.jobs.busy(p["id"])
        # These files sit in the analyzed folder, which may come from anyone: keep only the expected types.
        counts = sec.get("counts") if isinstance(sec.get("counts"), dict) else None
        grade, shape = rd.get("grade"), rd.get("shape")
        stack = rd.get("stack") if isinstance(rd.get("stack"), dict) else {}
        frameworks = [_str(x) for x in (stack.get("frameworks") or []) if _str(x)][:3]
        languages = [_str(x) for x in (stack.get("languages") or []) if _str(x)][:4]
        # The Projects screen's one sentence: how many open critical findings a visitor can reach, and from where.
        reach_crit, top_page = 0, None
        for f in (sec.get("findings") or []) if isinstance(sec.get("findings"), list) else []:
            if not isinstance(f, dict) or f.get("status") != "open" or f.get("rank") != "critical" or not f.get("reachable"):
                continue
            reach_crit += 1
            path = f.get("ui_path")
            if top_page is None and isinstance(path, list) and path and isinstance(path[0], str) and path[0].startswith("js:") and "::" in path[0]:
                top_page = path[0].rsplit("::", 1)[1].split(".")[0][:40]
        return {**p, "exists": Path(p["path"]).is_dir(), "has_report": (out / "report.html").exists(),
                "stack": " + ".join(frameworks) or " + ".join(languages) or None,
                "languages": languages, "reachable_critical": reach_crit, "top_page": top_page,
                "functions": _int(sec.get("total_callables")),
                "score": _int(rd.get("score")), "grade": grade if grade in ("A", "B", "C", "D", "F") else None,
                "shape": shape if shape in SHAPES else None,
                "counts": counts and {k: _int(counts.get(k)) or 0 for k in ("critical", "high", "medium", "low", "accepted")},
                "finished_at": _str(run.get("finished_at")),
                "explained": len(ex.get("explanations") or {}), "job": busy and busy["id"],
                "starter": learn.starter_of(Path(p["path"])), "stale": self._stale(out)}

    def _stale(self, out: Path) -> str | None:
        """'packs' when analysis packs were turned on or off after this report was made (the card says
        "Re-check to apply")."""
        pk = self.store.settings().get("packs")
        changed = pk.get("changed_at") if isinstance(pk, dict) else None
        try:
            made = (out / "report.html").stat().st_mtime
        except OSError:
            return None
        return "packs" if isinstance(changed, (int, float)) and changed > made else None

    def clone_project(self, link: str) -> dict:
        """A repository link pasted instead of a folder: the project is listed at once (so its card shows the job
        log), cloned under LANTERN_HOME/repos in a job, then analyzed. A failed clone forgets the project again."""
        info = remote.parse(link)   # ValueError for a bad link -> 400
        dest = remote.destination(info, self.store.root / "repos")
        dest.mkdir(parents=True, exist_ok=True)
        p = self.store.add_project(dest)
        privacy = self.store.settings().get("privacy", "full")

        def work(log):
            try:
                remote.clone(link, log=log, dest=dest)
            except Exception:
                if not remote.has_files(dest):   # nothing was cloned (a failed clone removes itself): forget the project
                    self.store.remove_project(p["id"])
                    if dest.is_dir():
                        remote.remove_tree(dest)
                raise
            return pipeline.analyze(dest, self.out(p), privacy, log=log)

        job = self.jobs.start(p["id"], "clone", work)
        return {"job": job, "project": self.summary(p)}

    def provider_info(self) -> list[dict]:
        from .providers import DATA_NOTICES, gateway_url, load_token
        allowance = bool(load_token() and gateway_url())
        rows = []
        for name, (_, url, env) in PRESETS.items():
            key = self.store.key_source(name)
            row = {"name": name, "local": name in LOCAL_PROVIDERS, "needs_key": bool(env), "env": env,
                   "default_url": url, "key": key, "notice": DATA_NOTICES.get(name, "")}
            if name == DEFAULT_PROVIDER:
                # No key needed while the free allowance lasts; the user's own key, once added, wins.
                row["default"] = True
                row["allowance"] = allowance and not key
                row["can_sign_in"] = bool(gateway_url()) and not allowance and not key
                if row["allowance"]:
                    row["needs_key"] = False
                    row["notice"] = DATA_NOTICES["lantern"]
            rows.append(row)
        rows.append({"name": "openai-compatible", "local": None, "needs_key": False, "env": "LANTERN_API_KEY",
                     "default_url": "", "key": self.store.key_source("openai-compatible")})
        return rows

    def make_provider(self):
        from .providers import make_provider
        s = self.store.settings()
        if not s.get("model"):
            raise ValueError("Choose a model in Settings first.")
        key = self.store.key_for(s["provider"])
        if s["provider"] == DEFAULT_PROVIDER and not key:
            from .providers import gateway_url, load_token
            if load_token() and gateway_url():
                return make_provider(f"lantern/{s['model']}")   # the free allowance
            raise ValueError(f"Add an {DEFAULT_PROVIDER} key in Settings, or run `lantern login --token <token>` "
                             "for the free allowance.")
        return make_provider(f"{s['provider']}/{s['model']}", base_url=s.get("base_url") or None, api_key=key)


def _same(given, token: str) -> bool:
    """Constant-time token check that also copes with missing or non-ASCII input (compare_digest raises on those)."""
    return isinstance(given, str) and hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8"))


def write_starter_file(repo: Path, out: Path, name: str) -> str:
    """Write one generated starter file next to the code; never over an existing file, never outside the repo."""
    rd = _load(out / "readiness.json") or {}
    f = (rd.get("starter") or {}).get(name)
    if not f or f.get("snippet"):
        raise ValueError(f"not a writable starter file: {name or '(none)'}; the names are those under Readiness → Starter files")
    dest = (repo / name).resolve()
    if repo.resolve() not in dest.parents:
        raise ValueError("outside the project")
    if dest.exists():
        raise ValueError(f"{name} already exists; Lantern never overwrites files")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(f["content"], encoding="utf-8")
    return name


TERMINAL_ALLOWED = ["analyze", "trace", "explain", "report", "verify", "accept", "packs", "export", "learn"]
TERMINAL_HELP = """Lantern commands only. The app runs each one the way its buttons do; results go to this project's .lantern/.
  analyze [--offline] [--no-scan] [--privacy full|structure]   read the project again and rebuild every result
  trace [--] TEST COMMAND                       run your tests in the sandbox (e.g. trace python -m pytest -q)
  explain [--node ID ...] [--depth N] [--max-nodes N]   explain functions with the model in Settings
  report [--privacy full|structure]             rebuild report.html from the saved results
  verify [--report FILE]                        re-run the analysis and compare it with the Evidence Report
  accept FINDING_ID --reason "..." [--by NAME]  record an accepted risk (or: accept FINDING_ID --remove)
  packs                                         list the analysis packs in use
  export [--sarif FILE]                         write findings as SARIF (default .lantern/findings.sarif)
  learn [--check]                               show the guide's progress for a starter app
Anything else (shell commands, python, rm, curl) is refused: this drawer never runs a shell or your code."""


class TerminalRefused(ValueError):
    """A drawer command outside the allow-list or with arguments it does not take; answered with 400 + the list."""


def _terminal_parser(verb: str):
    import argparse

    class P(argparse.ArgumentParser):
        def error(self, message):
            raise TerminalRefused(f"{verb}: {message}")

        def exit(self, status=0, message=None):
            raise TerminalRefused(f"{verb}: {message or 'refused'}")
    ap = P(prog=verb, add_help=False, allow_abbrev=False)
    ap.add_argument("--out", help=argparse.SUPPRESS)
    if verb == "analyze":
        ap.add_argument("--offline", action="store_true")
        ap.add_argument("--no-scan", action="store_true")
        ap.add_argument("--privacy", choices=["full", "structure"])
    elif verb == "explain":
        ap.add_argument("--node", action="append")
        ap.add_argument("--depth", type=int, default=3)
        ap.add_argument("--max-nodes", type=int, default=40)
        ap.add_argument("--fresh", action="store_true")
    elif verb == "report":
        ap.add_argument("--privacy", choices=["full", "structure"])
    elif verb == "verify":
        ap.add_argument("--report")
    elif verb == "accept":
        ap.add_argument("finding")
        ap.add_argument("--reason")
        ap.add_argument("--by")
        ap.add_argument("--remove", action="store_true")
    elif verb == "export":
        ap.add_argument("--sarif", default=".lantern/findings.sarif")
    elif verb == "learn":
        ap.add_argument("--check", action="store_true")
    return ap


def _inside(repo: Path, value: str, what: str) -> Path:
    """A path argument: relative to the project, and it must stay inside it (no `..`, no absolute escape, no symlink out)."""
    root = repo.resolve()
    target = (root / value).resolve()
    if target != root and root not in target.parents:
        raise TerminalRefused(f"{what} must be inside the project: {value}")
    return target


def run_terminal_command(app, p: dict, repo: Path, out: Path, argv) -> dict:
    """One drawer command, as an argv list (never a shell string). Allow-list only (`TERMINAL_ALLOWED`); `--out` is
    always the project's `.lantern/`; path arguments must resolve inside the project. Returns a job: its log is
    what the drawer prints. Every branch calls the function the matching button calls."""
    if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
        raise TerminalRefused("argv must be a list of strings")
    if len(argv) > 64 or any(len(a) > 2000 or "\x00" in a for a in argv):
        raise TerminalRefused("argv is too long")
    words = argv[1:] if argv[:1] == ["lantern"] else list(argv)
    if not words:
        raise TerminalRefused("type a Lantern command")
    verb, args = words[0], words[1:]
    if verb not in TERMINAL_ALLOWED:
        raise TerminalRefused(f"'{verb}' is not an allowed command")
    privacy_default = app.store.settings().get("privacy", "full")
    if verb == "trace":
        from . import sandbox
        cmd = args[1:] if args[:1] == ["--"] else args
        try:
            language = sandbox.check_command(cmd)
        except ValueError as e:
            raise TerminalRefused(f"trace: {e}") from None
        app.store.confirm_test(p["id"], " ".join(cmd))   # typed in full by the user: that is the confirmation
        det = sandbox.detect(repo)
        test_cwd = det.get("cwd", "") if det.get("language") == language else ""
        return {"job": app.jobs.start(p["id"], "trace", lambda log: pipeline.analyze(
            repo, out, privacy_default, trace_cmd=cmd, log=log, sandbox=True, test_cwd=test_cwd))}
    a = _terminal_parser(verb).parse_args(args)
    if a.out is not None and _inside(repo, a.out, "--out") != out.resolve():
        raise TerminalRefused("--out is always this project's .lantern/ folder")
    if verb == "analyze":
        privacy = a.privacy or privacy_default
        return {"job": app.jobs.start(p["id"], "analyze", lambda log: pipeline.analyze(
            repo, out, privacy, log=log, offline=a.offline or None, no_scan=a.no_scan))}
    if verb == "explain":
        if not (out / "graph.json").exists():
            raise TerminalRefused("explain: analyze the project first")
        if not (1 <= a.depth <= 10 and 1 <= a.max_nodes <= 400):
            raise TerminalRefused("explain: --depth 1-10, --max-nodes 1-400")
        provider = app.make_provider()

        def work(log):
            ids = a.node or pipeline.plan_explain(out, a.depth, a.max_nodes)["nodes"]
            log(f"explaining {len(ids)} function(s) with {provider.label}")
            res = pipeline.explain(out, provider, ids, fresh=a.fresh and bool(a.node), progress=lambda i, n, nid, rec: log(
                f"[{i}/{n}] {nid.split(':', 1)[-1]}  {'ok' if rec.get('validated') else 'rejected'}"))
            return {"stats": res["stats"]}
        return {"job": app.jobs.start(p["id"], "explain", work)}
    if verb == "report":
        if not (out / "graph.json").exists():
            raise TerminalRefused("report: analyze the project first")

        def work(log):
            if a.privacy:
                run = _load(out / "run.json") or {}
                run["privacy"] = a.privacy
                (out / "run.json").write_text(json.dumps(run, indent=1), encoding="utf-8")
            path = pipeline.rebuild_outputs(out)
            log(f"report  {path}")
            return {"report": str(path)}
        return {"job": app.jobs.start(p["id"], "report", work)}
    if verb == "verify":
        from . import evidence
        ev = _inside(repo, a.report, "--report") if a.report else out / "evidence.json"
        if not ev.exists():
            raise TerminalRefused("verify: this project has no Evidence Report yet; run analyze first")
        want, old = evidence.read_digest(ev)

        def work(log):
            r = evidence.verify(repo, want, old, trace_cmd=None, offline=False)
            log(f"{'MATCH' if r.get('match') else 'DIFFERENT'}: report {r.get('report')}  rerun {r.get('rerun')}")
            if not r.get("match"):
                log(str(r.get("note") or r.get("refused") or ""))
            return r
        return {"job": app.jobs.start(p["id"], "verify", work)}
    if verb == "accept":
        from .security import load_accepted, reason_ok, save_accepted
        acc = load_accepted(repo)
        if a.remove:
            if a.finding not in acc:
                raise TerminalRefused(f"accept: {a.finding} is not an accepted risk")
            acc.pop(a.finding)
        else:
            reason = (a.reason or "").strip()
            if not reason_ok(reason):
                raise TerminalRefused("accept: write a real reason (a sentence of at least 10 letters); it appears in the Evidence Report")
            sec = _load(out / "security.json") or {"findings": []}
            f = next((x for x in sec["findings"] if x["id"] == a.finding), None)
            if not f:
                raise TerminalRefused(f"accept: unknown finding {a.finding}")
            acc[a.finding] = {"id": a.finding, "rule": f["rule"], "file": f["file"], "line": f["line"], "title": f["title"],
                              "reason": reason, "by": (a.by or "me")[:80], "date": time.strftime("%Y-%m-%d")}
        save_accepted(repo, acc)
        note = f"{'removed' if a.remove else 'accepted'} {a.finding}; analyzing again so the score and the Evidence Report follow"

        def work(log):
            log(note)
            return pipeline.analyze(repo, out, privacy_default, log=log)
        return {"job": app.jobs.start(p["id"], "analyze", work)}
    if verb == "packs":
        from . import packs

        def work(log):
            loaded, problems = packs.load_all(repo, keep_inactive=True)
            for pk in loaded:
                req = pk.get("requires") or {}
                why = "" if pk["active"] else "  not used here: needs " + ", ".join(req.get("files", []) + req.get("text", []))
                log(f"{pk['pack']:<20} v{str(pk.get('version', '-')):<6} {len(pk.get('rules', [])):>2} rule(s), "
                    f"{len(pk.get('entries', []))} entry pattern(s)  [{pk['source']}]{why}")
            for where, msg in problems:
                log(f"skipped {where}: {msg}")
            return {"packs": len(loaded), "problems": len(problems)}
        return {"job": app.jobs.start(p["id"], "packs", work)}
    if verb == "export":
        from .exporters import sarif
        dest = _inside(repo, a.sarif, "--sarif")
        sec = _load(out / "security.json")
        if sec is None:
            raise TerminalRefused("export: analyze the project first")

        def work(log):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps(sarif(sec, repo), indent=1), encoding="utf-8")
            log(f"wrote   {dest.relative_to(repo.resolve()).as_posix()}  ({len(sec.get('findings', []))} findings)")
            return {"wrote": str(dest)}
        return {"job": app.jobs.start(p["id"], "export", work)}
    # learn
    from . import learn as learn_mod
    sid = learn_mod.starter_of(repo)

    def work(log):
        if not sid:
            log("this project is not a starter app; Learn → Create one")
            return {}
        pr = learn_mod.progress(sid, repo, out)
        log(f"{sid}: {pr.get('done', 0)} of {pr.get('total', 0)} steps done")
        for st in pr.get("steps", []) if a.check else []:
            log(f"  {'done' if st.get('done') else 'todo'}  {st.get('title', st.get('id', ''))}")
        return pr
    return {"job": app.jobs.start(p["id"], "learn", work)}


def packs_list(app, pid: str = "", all_projects: bool = False) -> list[dict]:
    """GET /api/packs: built-in and user packs, plus the project's own when `pid` names one (every project's with
    `all_projects`). Shape per pack: name, version, source (builtin|project|user), rules, entry_patterns, path,
    enabled, active (its `requires` match the project), about."""
    from . import packs
    projects = app.store.projects() if all_projects else [x for x in [app.store.project(pid)] if x] if pid else []
    seen, rows = set(), []
    for repo in [Path(x["path"]) for x in projects if Path(x["path"]).is_dir()] or [None]:
        loaded, _ = packs.load_all(repo, keep_inactive=True)
        for pk in loaded:
            if pk["pack"] in seen:
                continue
            seen.add(pk["pack"])
            where = {"builtin": "lantern/packs/", "project": packs.PROJECT_DIR + "/", "user": "~/.lantern/packs/"}[pk["source"]]
            rows.append({"name": pk["pack"], "version": str(pk.get("version", "-")), "source": pk["source"],
                         "rules": len(pk.get("rules", [])), "entry_patterns": len(pk.get("entries", [])),
                         "path": where + pk["file"], "enabled": pk.get("enabled", True),
                         "active": bool(pk.get("active", True)) if repo is not None else None,
                         "about": str(pk.get("about") or "")[:300]})
    return rows


def detect_test_command(repo: Path) -> dict:
    """The command the sheet shows first (see `sandbox.detect`), plus which sandbox will run it."""
    from . import sandbox
    d = sandbox.detect(repo)
    d["sandbox"] = sandbox.describe(repo, d["language"])
    d["leaves"] = "Nothing leaves this computer: the tests run with the network off."
    return d


def _csp(nonce: str | None) -> str:
    """Only our own scripts run on Lantern's pages: inline ones carry this response's nonce, and pages without
    a nonce (messages) run none at all."""
    script = f"'nonce-{nonce}'" if nonce else "'none'"
    # Google Fonts is the one outside origin: the design's typefaces (DM Sans, Lora, JetBrains Mono). Offline, the
    # system fallbacks render and nothing else changes; the browser sends no cookies to it.
    return (f"default-src 'self'; script-src {script}; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
            "worker-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
            "frame-ancestors 'self'")


def _int(v):
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _str(v):
    return v[:80] if isinstance(v, str) else None


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
    except (OSError, json.JSONDecodeError):
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = f"lantern/{__version__}"
    app: App  # set by serve()

    def log_message(self, fmt, *args):  # quiet by default
        if os.environ.get("LANTERN_DEBUG"):
            super().log_message(fmt, *args)

    # ------------------------------------------------------------------ plumbing
    def _send(self, code: int, body: bytes | str, ctype: str = "application/json", headers: dict | None = None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, data, code=200, headers=None):
        self._send(code, json.dumps(data), headers=headers)

    def _err(self, code: int, msg: str):
        self._json({"error": msg}, code)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        ctype = self.headers.get("Content-Type") or ""
        if ctype.startswith("multipart/form-data"):
            if n > 12_000_000:
                raise ValueError("file too large (12 MB max)")
            return {"_multipart": self.rfile.read(n), "_ctype": ctype}
        if n > 1_000_000:
            raise ValueError("request too large")
        raw = self.rfile.read(n) if n else b"{}"
        data = json.loads(raw or b"{}")
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        return data

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        allowed = {f"127.0.0.1:{self.app.port}", f"localhost:{self.app.port}", f"[::1]:{self.app.port}"}
        extra = os.environ.get("LANTERN_ALLOWED_HOST")
        if extra:
            allowed.add(extra.lower())
        return host in allowed

    def _cookie_token(self) -> str | None:
        c = SimpleCookie(self.headers.get("Cookie") or "")
        return c["lantern_token"].value if "lantern_token" in c else None

    def _authed(self, write: bool) -> bool:
        tok = self.app.token
        if write:
            return _same(self.headers.get("X-Lantern-Token"), tok)
        return _same(self._cookie_token(), tok)

    # ------------------------------------------------------------------ dispatch
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._host_ok():
            return self._err(403, "unexpected Host header")
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/manifest.webmanifest", "/sw.js", "/icon.svg"):
            return self._static(u.path[1:])
        if u.path == "/":
            given = (q.get("token") or [""])[0]
            if given and _same(given, self.app.token):
                # set the cookie, then drop the token from the address bar
                return self._send(303, "", "text/plain", {
                    "Location": "/", "Set-Cookie": f"lantern_token={self.app.token}; HttpOnly; SameSite=Strict; Path=/"})
            if not self._authed(False):
                return self._send(403, LOCKED_PAGE, "text/html; charset=utf-8")
            nonce = secrets.token_urlsafe(16)
            html = (VIEWER / "app.html").read_text(encoding="utf-8").replace("__LANTERN_TOKEN__", self.app.token).replace(
                "__LANTERN_VERSION__", __version__).replace("<script>", f'<script nonce="{nonce}">')
            return self._send(200, html, "text/html; charset=utf-8", {"Content-Security-Policy": _csp(nonce)})
        if not self._authed(False):
            return self._err(403, "open the link printed by `lantern serve`")
        try:
            return self._get(u.path, q)
        except Exception as exc:  # noqa: BLE001
            return self._err(500, f"{type(exc).__name__}: {exc}")

    def do_POST(self):
        self._write("POST")

    def do_DELETE(self):
        self._write("DELETE")

    def _write(self, method: str):
        if not self._host_ok():
            return self._err(403, "unexpected Host header")
        if not self._authed(True):
            return self._err(403, "missing or wrong X-Lantern-Token")
        try:
            body = self._body()
            return self._post(method, urlparse(self.path).path, body)
        except (ValueError, json.JSONDecodeError) as exc:
            return self._err(400, str(exc))
        except RuntimeError as exc:
            return self._err(409, str(exc))
        except Exception as exc:  # noqa: BLE001
            return self._err(500, f"{type(exc).__name__}: {exc}")

    def _static(self, name: str):
        p = VIEWER / name
        ctype = {"webmanifest": "application/manifest+json", "js": "text/javascript", "svg": "image/svg+xml"}[
            name.rsplit(".", 1)[1]]
        self._send(200, p.read_bytes(), ctype)

    def _result_file(self, p: dict, name: str):
        """Serve a result page. Files in `.lantern/` sit inside the analyzed folder, so a cloned repo can plant them:
        never send their bytes as a page. Read only the data back and rebuild every page from our own templates,
        with a per-response nonce so nothing but our scripts can run."""
        from .evidence import badge_svg, render_html
        from .report import read_bundle, render
        f = self.app.out(p) / name.replace("badge.svg", "readiness.json")
        if not f.exists():
            return self._send(404, "<p>Not analyzed yet.</p>", "text/html; charset=utf-8",
                              {"Content-Security-Policy": _csp(None)})
        try:
            if name == "report.html":
                usage.record("report_open")
                s = self.app.store.settings()
                live = {"api": f"/api/projects/{p['id']}", "token": self.app.token, "model": s.get("model") and
                        f"{s['provider']}/{s['model']}", "local": s.get("provider") in LOCAL_PROVIDERS}
                nonce = secrets.token_urlsafe(16)
                return self._send(200, render(read_bundle(f), live, nonce), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": _csp(nonce)})
            if name == "evidence.html":
                ev = _load(f.with_suffix(".json"))
                nonce = secrets.token_urlsafe(16)   # the page's one script: Simple/Advanced, copy the verify command
                return self._send(200, render_html(ev, nonce), "text/html; charset=utf-8", {"Content-Security-Policy": _csp(nonce)})
            if name == "badge.svg":
                rd = _load(f) or {}
                ev = _load(f.with_name("evidence.json")) or {}
                grade = rd.get("grade") if rd.get("grade") in ("A", "B", "C", "D", "F") else "?"
                # only the fields the badge shows are read back from the (plantable) file, and each is coerced
                now = (ev.get("scorecard") or {}).get("now") if isinstance(ev.get("scorecard"), dict) else {}
                safe = {"header": {"commit": re.sub(r"[^0-9a-f]", "", str((ev.get("header") or {}).get("commit") or ""))[:40] or None,
                                   "generated_at": _str((ev.get("header") or {}).get("generated_at"))},
                        "scorecard": {"now": {k: _int((now or {}).get(k)) or 0 for k in ("critical", "high")} if now else {}}}
                return self._send(200, badge_svg(_int(rd.get("score")) or 0, grade, safe), "image/svg+xml",
                                  {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
            return self._send(200, json.dumps(_load(f)), "application/json")
        except Exception as exc:  # noqa: BLE001: a damaged or hand-made file
            return self._send(409, f"<p>This result file can't be read ({html.escape(type(exc).__name__)}). "
                              "Analyze the project again.</p>", "text/html; charset=utf-8", {"Content-Security-Policy": _csp(None)})

    # ------------------------------------------------------------------ GET routes
    def _get(self, path: str, q: dict):
        app = self.app
        if path == "/api/state":
            s = app.store.settings()
            return self._json({"version": __version__, "projects": [app.summary(p) for p in app.store.projects()],
                               "settings": s, "providers": app.provider_info(),
                               "default_model": {"provider": DEFAULT_PROVIDER, "model": DEFAULT_MODEL_NAME}})
        if path == "/api/usage":
            from .providers import gateway_url
            return self._json({"enabled": usage.enabled(), "gateway": bool(gateway_url()), "pending": usage.pending(),
                               "features": sorted(usage.FEATURES), "text": usage.describe()})
        if path == "/api/packs":
            return self._json({"packs": packs_list(app, (q.get("project") or [""])[0])})
        if path == "/api/connections":
            import shutil
            from .mcp_server import connections
            cmd = shutil.which("lantern") or "lantern"
            return self._json({"connections": connections(app.store), "now": int(time.time()),
                               "setup": {"claude_code": f"claude mcp add lantern -- {cmd} mcp",
                                         "json": {"mcpServers": {"lantern": {"command": cmd, "args": ["mcp"]}}}}})
        if path == "/api/login/poll":
            from .providers import ProviderError, save_token, sign_in_claim
            cli = (q.get("cli") or [""])[0]
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", cli):
                return self._err(400, "bad cli code")
            try:
                tok = sign_in_claim(cli)
            except ProviderError as e:
                return self._json({"done": False, "error": str(e)[:200]})
            if not tok:
                return self._json({"done": False})
            save_token(tok)
            usage.record("settings_save")
            return self._json({"done": True})
        if path == "/api/allowance":
            from .providers import ProviderError, allowance_status, gateway_url, load_token
            if not (load_token() and gateway_url()):
                return self._json({"available": False})
            try:
                return self._json({"available": True, **allowance_status()})
            except ProviderError as e:
                return self._json({"available": False, "error": str(e)[:200]})
        m = re.fullmatch(r"/api/jobs/(\w+)", path)
        if m:
            j = app.jobs.jobs.get(m.group(1))
            return self._json(j) if j else self._err(404, "no such job")
        if path == "/api/fs":
            return self._json(_list_dir((q.get("path") or [""])[0]))
        if path == "/api/starters":
            return self._json({"starters": learn.catalog(), "default_parent": str(Path.home() / "lantern-starters")})
        m = re.fullmatch(r"/api/starters/([\w-]+)(/fix)?", path)
        if m and m.group(1) not in learn.ids():
            return self._err(404, "unknown starter")
        if m and not m.group(2):
            s = learn.get(m.group(1))
            return self._json({k: s.get(k) for k in ("id", "title", "stack", "minutes", "summary", "run", "steps")})
        if m:
            text = learn.solution_text(m.group(1), (q.get("file") or [""])[0])
            return self._json({"text": text}) if text is not None else self._err(404, "no fixed version of that file")
        m = re.fullmatch(r"/api/projects/(\w+)/learn", path)
        if m:
            p = app.store.project(m.group(1))
            sid = p and learn.starter_of(Path(p["path"]))
            if not sid:
                return self._err(404, "this project wasn't created from a starter")
            return self._json(learn.progress(sid, Path(p["path"]), app.out(p)))
        m = re.fullmatch(r"/api/projects/(\w+)/testcmd", path)
        if m:
            p = app.store.project(m.group(1))
            if not p:
                return self._err(404, "unknown project")
            d = detect_test_command(Path(p["path"]))
            d["confirmed"] = d["command"] in app.store.confirmed_tests(p["id"])
            return self._json(d)
        m = re.fullmatch(r"/api/projects/(\w+)/plan", path)
        if m:
            p = app.store.project(m.group(1)) or {}
            if not p or not (Path(p["path"]) / ".lantern/graph.json").exists():
                return self._err(404, "analyze the project first")
            plan = pipeline.plan_explain(app.out(p), int((q.get("depth") or ["3"])[0]),
                                         int((q.get("limit") or ["40"])[0]))
            plan["nodes"] = len(plan["nodes"])
            return self._json(plan)
        m = re.fullmatch(r"/api/projects/(\w+)/explanation", path)
        if m:
            p = app.store.project(m.group(1))
            ex = _load(app.out(p) / "explanations.json") if p else None
            rec = ((ex or {}).get("explanations") or {}).get((q.get("node") or [""])[0])
            return self._json({"record": rec, "metaphor": (ex or {}).get("metaphor")})
        m = re.fullmatch(r"/p/(\w+)/(report\.html|evidence\.html|badge\.svg|evidence\.json)", path)
        if m:
            p = app.store.project(m.group(1))
            if not p:
                return self._err(404, "unknown project")
            return self._result_file(p, m.group(2))
        return self._err(404, "not found")

    # ------------------------------------------------------------------ write routes
    def _post(self, method: str, path: str, b: dict):
        app = self.app
        if path == "/api/projects" and method == "POST":
            raw = str(b.get("path") or "").strip()
            if not raw:
                raise ValueError("give a folder path or a repository link")
            if remote.looks_like_url(raw):
                usage.record("analyze_link")
                return self._json(app.clone_project(raw), 202)
            d = Path(os.path.expanduser(raw))
            if not d.is_dir():
                raise ValueError(f"not a folder: {raw}")
            return self._json(app.summary(app.store.add_project(d)))
        if path == "/api/starters" and method == "POST":
            s = learn.get(str(b.get("id") or ""))
            parent = Path(os.path.expanduser(str(b.get("parent") or "").strip() or Path.home() / "lantern-starters"))
            dest = parent / s["id"]
            n = 2
            while dest.exists():
                dest, n = parent / f"{s['id']}-{n}", n + 1
            learn.scaffold(s["id"], dest)
            proj = app.store.add_project(dest)
            privacy = app.store.settings().get("privacy", "full")
            job = app.jobs.start(proj["id"], "analyze", lambda log: pipeline.analyze(dest, app.out(proj), privacy, log=log))
            return self._json({"project": app.summary(proj), "job": job}, 201)
        if path == "/api/ask/screenshot":
            from . import ask as _ask
            return self._json(_ask.read_screenshot(b.get("_multipart") or b"", str(b.get("_ctype") or "")))
        if path == "/api/ask":
            from . import ask as _ask
            pid = str(b.get("project") or "")
            proj = app.store.project(pid) if pid else None
            if pid and not proj:
                raise ValueError("no such project")
            try:
                provider = app.make_provider()
            except ValueError as e:
                return self._json({"answer": f"No model is set up yet, so I can't answer in words. {e} "
                                             "Everything else in Lantern works without a model.", "no_model": True})
            usage.record("explain_one")
            res = _ask.ask(provider, str(b.get("question") or ""), Path(proj["path"]) if proj else None,
                           b.get("focus") if isinstance(b.get("focus"), dict) else None)
            return self._json(res)
        if path == "/api/login/start":
            from .providers import sign_in_start
            provider = str(b.get("provider") or "")
            if provider not in ("github", "google"):
                raise ValueError("provider is github or google")
            return self._json(sign_in_start(provider))
        if path == "/api/packs":
            # Settings → Analysis packs: turn one pack on or off for every project. Reports made before the change
            # are marked stale ("Re-check to apply"); nothing is re-analyzed by itself.
            name, enabled = str(b.get("name") or ""), b.get("enabled")
            if not isinstance(enabled, bool):
                raise ValueError("enabled must be true or false")
            if name not in {x["name"] for x in packs_list(app, "", all_projects=True)}:
                raise ValueError(f"no analysis pack called {name!r}")
            s = app.store.settings()
            pk = s.get("packs") if isinstance(s.get("packs"), dict) else {}
            off = set(pk.get("disabled") or [])
            off = off - {name} if enabled else off | {name}
            s["packs"] = {"disabled": sorted(off), "changed_at": time.time()}
            app.store.save_settings(s)
            return self._json({"ok": True, "packs": packs_list(app, str(b.get("project") or ""))})
        if path == "/api/settings":
            s = app.store.settings()
            for k in ("provider", "model", "base_url", "privacy"):
                if k in b and b[k] is not None:
                    s[k] = str(b[k]).strip()
            if s["provider"] not in PRESETS and s["provider"] != "openai-compatible":
                raise ValueError("unknown provider")
            if s["privacy"] not in ("full", "structure"):
                raise ValueError("privacy is full or structure")
            if "share_usage" in b:
                s["share_usage"] = bool(b["share_usage"])
            for k in ("view_mode", "backdrop"):
                if k in b and b[k] is not None:
                    s[k] = str(b[k])
            app.store.save_settings(s)
            usage.record("settings_save")
            if b.get("key"):
                app.store.set_key(s["provider"], str(b["key"]).strip(), bool(b.get("remember")))
            if b.get("forget_key"):
                app.store.forget_key(s["provider"])
            return self._json({"settings": app.store.settings(), "providers": app.provider_info()})
        m = re.fullmatch(r"/api/projects/(\w+)(?:/(\w+))?", path)
        if not m:
            return self._err(404, "not found")
        p = app.store.project(m.group(1))
        if not p:
            return self._err(404, "unknown project")
        action = m.group(2)
        repo, out = Path(p["path"]), app.out(p)
        if method == "DELETE" and not action:
            app.store.remove_project(p["id"])
            return self._json({"ok": True, "note": "Removed from the list. Files were not touched."})
        if action == "analyze":
            usage.record("analyze")
            privacy = app.store.settings().get("privacy", "full")
            job = app.jobs.start(p["id"], "analyze", lambda log: pipeline.analyze(repo, out, privacy, log=log))
            return self._json(job, 202)
        if action == "cmd":
            # The terminal drawer: Lantern commands only, run through the same code paths as the buttons.
            try:
                return self._json(run_terminal_command(app, p, repo, out, b.get("argv")), 202)
            except TerminalRefused as e:
                return self._json({"error": str(e), "allowed": TERMINAL_ALLOWED, "help": TERMINAL_HELP}, 400)
        if action == "trace":
            # "Watch my tests run": the confirmed test command runs in the sandbox (lantern/sandbox.py: Docker, or a
            # restricted process on a read-only temp copy), then the project is analyzed again so the calls the
            # tests made become "seen running". The user confirms once per project per command.
            usage.record("trace")
            from . import sandbox
            cmd = str(b.get("command") or "").strip()
            words = sandbox.split(cmd)
            language = sandbox.check_command(words)   # ValueError -> 400 with the accepted runners
            canon = " ".join(words)
            if not b.get("confirm") and canon not in app.store.confirmed_tests(p["id"]):
                return self._err(409, "confirm this command first: the sheet shows what will run and where")
            app.store.confirm_test(p["id"], canon)
            det = sandbox.detect(repo)
            test_cwd = det.get("cwd", "") if det.get("language") == language else ""
            privacy = app.store.settings().get("privacy", "full")
            before = _load(out / "readiness.json") or {}
            before_score = _int(before.get("score"))

            def work(log):
                res = pipeline.analyze(repo, out, privacy, trace_cmd=words, log=log, sandbox=True, test_cwd=test_cwd)
                run = _load(out / "run.json") or {}
                tr = run.get("trace") or {}
                after = _load(out / "readiness.json") or {}
                return {"returncode": tr.get("returncode"), "observed": tr.get("observed_edges"), "recall": tr.get("recall"),
                        "backend": tr.get("backend"), "language": tr.get("language"), "traced": tr.get("traced"),
                        "timed_out": tr.get("timed_out"), "blocked": tr.get("blocked") or [],
                        "note": None if tr.get("traced") else sandbox.JS_NOTE,
                        "score_before": before_score, "score_after": _int(after.get("score")), "summary": res}
            return self._json(app.jobs.start(p["id"], "trace", work), 202)
        if action == "explain":
            usage.record("explain_one" if b.get("nodes") else "explain")
            provider = app.make_provider()
            nodes = b.get("nodes")
            if nodes is not None and (not isinstance(nodes, list) or not all(isinstance(n, str) for n in nodes)):
                raise ValueError("nodes must be a list of node ids")
            if not (out / "graph.json").exists():
                raise ValueError("analyze the project first")

            def work(log):
                ids = nodes or pipeline.plan_explain(out, int(b.get("depth") or 3), int(b.get("limit") or 40))["nodes"]
                log(f"explaining {len(ids)} function(s) with {provider.label}")

                def progress(i, n, nid, rec):
                    flag = "ok" if rec.get("validated") else ("error: " + rec["error"][:120] if "error" in rec
                                                              else "rejected by the anchor check")
                    log(f"[{i}/{n}] {nid.split(':', 1)[-1]}  {flag}")

                res = pipeline.explain(out, provider, ids, progress=progress, fresh=bool(b.get("fresh")) and bool(nodes))
                st = res["stats"]
                log(f"done: {st['validated']} validated, {st['failed']} failed, {st['cached']} from cache; "
                    f"{st['usage']['input_tokens']:,} tokens in, {st['usage']['output_tokens']:,} out")
                rem = getattr(provider, "remaining", None)
                if rem and rem.get("requests") is not None:
                    log(f"free explanations left: {rem['requests']}")
                if st.get("stopped"):
                    log(f"stopped early: {st['stopped']}")
                return {"stats": st}
            return self._json(app.jobs.start(p["id"], "explain", work), 202)
        if action == "accept":
            usage.record("accept")
            from .security import load_accepted, reason_ok, save_accepted
            fid, reason = str(b.get("finding") or ""), str(b.get("reason") or "").strip()
            if b.get("remove"):
                acc = load_accepted(repo)
                acc.pop(fid, None)
                save_accepted(repo, acc)
            else:
                sec = _load(out / "security.json") or {"findings": []}
                f = next((x for x in sec["findings"] if x["id"] == fid), None)
                if not f:
                    raise ValueError("unknown finding")
                if not reason_ok(reason):
                    raise ValueError("write a real reason (a sentence of at least 10 letters); it appears in the Evidence Report")
                acc = load_accepted(repo)
                acc[fid] = {"id": fid, "rule": f["rule"], "file": f["file"], "line": f["line"], "title": f["title"],
                            "reason": reason, "by": str(b.get("by") or "me")[:80], "date": time.strftime("%Y-%m-%d")}
                save_accepted(repo, acc)
            privacy = app.store.settings().get("privacy", "full")
            job = app.jobs.start(p["id"], "analyze", lambda log: pipeline.analyze(repo, out, privacy, log=log))
            return self._json(job, 202)
        if action == "starter":
            usage.record("starter")
            return self._json({"ok": True, "wrote": write_starter_file(repo, out, str(b.get("name") or ""))})
        return self._err(404, "not found")


def _list_dir(raw: str) -> dict:
    d = Path(os.path.expanduser(raw or "~")).resolve()
    if not d.is_dir():
        d = Path.home()
    dirs = []
    try:
        for c in sorted(d.iterdir(), key=lambda x: x.name.lower()):
            if c.is_dir() and not c.name.startswith(".") and c.name not in ("node_modules", "__pycache__"):
                marks = [m for m in ("package.json", "pyproject.toml", "requirements.txt", ".git") if (c / m).exists()]
                dirs.append({"name": c.name, "path": str(c), "project": bool(marks)})
    except OSError:
        pass
    return {"path": str(d), "parent": str(d.parent) if d.parent != d else None, "dirs": dirs[:500]}


LOCKED_PAGE = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lantern</title><body style="font:15px/1.5 system-ui,sans-serif;max-width:520px;margin:15vh auto;padding:0 16px">
<h1 style="font-size:20px">Lantern is running</h1><p>For safety, open the link that <code>lantern serve</code> printed
in your terminal (it contains a one-time token). Run <code>lantern serve</code> again to get a new link.</p></body>"""


def _usage_sender() -> None:
    """Send opt-in usage counts now and then every six hours, in the background, never blocking the app."""
    from .providers import gateway_url

    def loop():
        while True:
            usage.send(gateway_url())
            time.sleep(6 * 3600)
    threading.Thread(target=loop, daemon=True).start()


def _unspecified(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def serve(paths: list[str], host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True,
          analyze_first: bool = True, check: bool = False) -> int:
    """`check`: start, print the link, fetch the home page once through it, stop. Adds no project, runs no
    analysis, opens no browser and sends nothing; exits 0 only if the page came back (used by install tests)."""
    missing = [p for p in paths if not Path(p).is_dir()]
    if check and missing:
        print(f"not a folder: {', '.join(missing)}")
        return 2
    store = Store(home_dir())
    added = [] if check else [store.add_project(Path(p)) for p in paths if Path(p).is_dir()]
    httpd = None
    for candidate in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer((host, candidate), Handler)
            port = candidate
            break
        except OSError:
            continue
    if httpd is None:
        print(f"could not find a free port near {port}")
        return 1
    token = secrets.token_urlsafe(24)
    app = App(store, token, port)
    Handler.app = app
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: listening beyond this computer. Anyone who has the link below can use Lantern as you.")
        os.environ.setdefault("LANTERN_ALLOWED_HOST", f"{host}:{port}")
    for p in added:
        if analyze_first and not (Path(p["path"]) / ".lantern" / "report.html").exists():
            privacy = store.settings().get("privacy", "full")
            repo = Path(p["path"])
            app.jobs.start(p["id"], "analyze",
                           lambda log, repo=repo: pipeline.analyze(repo, pipeline.out_dir(repo), privacy, log=log))
    url = f"http://{'127.0.0.1' if _unspecified(host) else host}:{port}/?token={token}"
    if check:
        print(f"Lantern {__version__} is running. Open:\n\n  {url}\n", flush=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        import urllib.request   # the token link sets the cookie, then redirects to the app
        local = f"http://127.0.0.1:{port}/?token={token}" if _unspecified(host) else url
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor()).open(local, timeout=20) as r:
                ok = r.status == 200 and b"Lantern" in r.read()
        except OSError as e:
            print(f"check failed: {e}")
            ok = False
        finally:
            httpd.shutdown()
            httpd.server_close()
        print("check   the app answered; stopped" if ok else "check   the app did not answer")
        return 0 if ok else 1
    print(f"Lantern {__version__} is running. Open:\n\n  {url}\n\nPress Ctrl-C to stop.", flush=True)
    usage.record("serve")
    _usage_sender()
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
