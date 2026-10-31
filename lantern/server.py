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
import threading
import time
import traceback
import uuid
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, learn, pipeline, remote
from .providers import PRESETS
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
        return {"provider": "anthropic", "model": "", "base_url": "", "privacy": "full",
                **self._read("settings.json", {})}

    def save_settings(self, s: dict) -> None:
        keep = {k: s.get(k) for k in ("provider", "model", "base_url", "privacy")}
        with self.lock:
            self._write("settings.json", keep)

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
        return {**p, "exists": Path(p["path"]).is_dir(), "has_report": (out / "report.html").exists(),
                "score": _int(rd.get("score")), "grade": grade if grade in ("A", "B", "C", "D", "F") else None,
                "shape": shape if shape in SHAPES else None,
                "counts": counts and {k: _int(counts.get(k)) or 0 for k in ("critical", "high", "medium", "low", "accepted")},
                "finished_at": _str(run.get("finished_at")),
                "explained": len(ex.get("explanations") or {}), "job": busy and busy["id"],
                "starter": learn.starter_of(Path(p["path"]))}

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
        rows = []
        for name, (_, url, env) in PRESETS.items():
            rows.append({"name": name, "local": name in LOCAL_PROVIDERS, "needs_key": bool(env), "env": env,
                         "default_url": url, "key": self.store.key_source(name)})
        rows.append({"name": "openai-compatible", "local": None, "needs_key": False, "env": "LANTERN_API_KEY",
                     "default_url": "", "key": self.store.key_source("openai-compatible")})
        return rows

    def make_provider(self):
        from .providers import make_provider
        s = self.store.settings()
        if not s.get("model"):
            raise ValueError("Choose a model in Settings first.")
        return make_provider(f"{s['provider']}/{s['model']}", base_url=s.get("base_url") or None,
                             api_key=self.store.key_for(s["provider"]))


def _same(given, token: str) -> bool:
    """Constant-time token check that also copes with missing or non-ASCII input (compare_digest raises on those)."""
    return isinstance(given, str) and hmac.compare_digest(given.encode("utf-8"), token.encode("utf-8"))


def _csp(nonce: str | None) -> str:
    """Only our own scripts run on Lantern's pages: inline ones carry this response's nonce, and pages without
    a nonce (Evidence Report, messages) run none at all."""
    script = f"'nonce-{nonce}'" if nonce else "'none'"
    return (f"default-src 'self'; script-src {script}; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
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
                s = self.app.store.settings()
                live = {"api": f"/api/projects/{p['id']}", "token": self.app.token, "model": s.get("model") and
                        f"{s['provider']}/{s['model']}", "local": s.get("provider") in LOCAL_PROVIDERS}
                nonce = secrets.token_urlsafe(16)
                return self._send(200, render(read_bundle(f), live, nonce), "text/html; charset=utf-8",
                                  {"Content-Security-Policy": _csp(nonce)})
            if name == "evidence.html":
                ev = _load(f.with_suffix(".json"))
                return self._send(200, render_html(ev), "text/html; charset=utf-8", {"Content-Security-Policy": _csp(None)})
            if name == "badge.svg":
                rd = _load(f) or {}
                grade = rd.get("grade") if rd.get("grade") in ("A", "B", "C", "D", "F") else "?"
                return self._send(200, badge_svg(_int(rd.get("score")) or 0, grade), "image/svg+xml",
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
                               "settings": s, "providers": app.provider_info()})
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
        if path == "/api/settings":
            s = app.store.settings()
            for k in ("provider", "model", "base_url", "privacy"):
                if k in b and b[k] is not None:
                    s[k] = str(b[k]).strip()
            if s["provider"] not in PRESETS and s["provider"] != "openai-compatible":
                raise ValueError("unknown provider")
            if s["privacy"] not in ("full", "structure"):
                raise ValueError("privacy is full or structure")
            app.store.save_settings(s)
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
            privacy = app.store.settings().get("privacy", "full")
            job = app.jobs.start(p["id"], "analyze", lambda log: pipeline.analyze(repo, out, privacy, log=log))
            return self._json(job, 202)
        if action == "explain":
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

                res = pipeline.explain(out, provider, ids, progress=progress)
                st = res["stats"]
                log(f"done: {st['validated']} validated, {st['failed']} failed, {st['cached']} from cache; "
                    f"{st['usage']['input_tokens']:,} tokens in, {st['usage']['output_tokens']:,} out")
                return {"stats": st}
            return self._json(app.jobs.start(p["id"], "explain", work), 202)
        if action == "accept":
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
            rd = _load(out / "readiness.json") or {}
            name = str(b.get("name") or "")
            f = (rd.get("starter") or {}).get(name)
            if not f or f.get("snippet"):
                raise ValueError("not a writable starter file")
            dest = (repo / name).resolve()
            if repo.resolve() not in dest.parents:
                raise ValueError("outside the project")
            if dest.exists():
                raise ValueError(f"{name} already exists; Lantern never overwrites files")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f["content"], encoding="utf-8")
            return self._json({"ok": True, "wrote": name})
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


def _unspecified(host: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return False


def serve(paths: list[str], host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True,
          analyze_first: bool = True) -> int:
    store = Store(home_dir())
    added = [store.add_project(Path(p)) for p in paths if Path(p).is_dir()]
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
    print(f"Lantern {__version__} is running. Open:\n\n  {url}\n\nPress Ctrl-C to stop.", flush=True)
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
    return 0
