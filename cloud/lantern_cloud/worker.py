"""The job runner: clone → audits → analysis → results, with the clone deleted at the end whatever happened.

One run, step by step (docs/cloud-mode-brief.md §3):
  1. `remote.clone` into a fresh temp folder (https only, allowed hosts, no credentials, refused above the size cap
     before any file is written). This step needs the network and handles only bytes, no code.
  2. The dependency audits (`python -m lantern.depaudit`): lock files and `==` pins only, nothing installed, inside
     the restricted process (`lantern._jail`: rlimits, Landlock writes only in the temp folder), network allowed
     because the vulnerability databases are online.
  3. The analysis (`python -m lantern.cli analyze --offline`) inside the restricted process with **no network**
     (Landlock TCP off where the kernel has it, plus the sandbox's audit hook) and writes only in its temp folder;
     the audit results from step 2 come in through LANTERN_AUDITS_FROM.
  4. The result files are copied to the run's folder; the temp folder (clone included) is removed in `finally`.

Plain-words explanations (`explain`, when the owner asks and has agreed to send code to the model): the clone is
gone by then, so the repository is copied again at the run's commit (a different commit is refused, so the words
match the map), `lantern explain` runs in the restricted process with the network on (it talks to the gateway with
the person's own allowance token, passed in the environment and held only in memory while the job waits), the new
explanations and the rebuilt report are copied back, and the copy is deleted again.

The analysed code is never executed: no builds, installs, tests or tracing. This is the same reason the local app
can analyse a stranger's repository; the sandbox is a second wall in case the analyser itself is tricked.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from lantern import learn, remote, sandbox

from .ghapp import NoAccess
from .settings import Settings
from .store import Store

RESULT_FILES = ("report.html", "evidence.html", "evidence.json", "graph.json", "security.json", "readiness.json",
                "run.json", "badge.svg")
EXPLAINED_FILES = ("explanations.json", "report.html", "evidence.html", "evidence.json")   # what `explain` rewrites
ACTIVE_EXPLAIN = ("queued", "running")
EXPLAIN_MAX = 40       # functions explained per click (entry points and three levels down, as in the app)
STAGES = {"clone": "Copying the repository (nothing is run or installed)",
          "unpack": "Unpacking your upload (nothing is run or installed)",
          "audit": "Checking dependency versions against public advisories",
          "analyze": "Mapping the code and running the checks",
          "save": "Saving your results"}
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
              "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")


UPLOAD_EXPLAIN = ("An uploaded app is deleted when its check ends, so Lantern cannot read its code again to explain it. "
                  "Explanations work for apps checked from a link, or in the Lantern app on your computer.")


class RunFailed(Exception):
    """A plain sentence for the person, and the status to record (`error` or `blocked`)."""

    def __init__(self, message: str, status: str = "error"):
        super().__init__(message)
        self.status = status


def clone_repo(link: str, dest: Path, log, token: str | None = None) -> Path:
    """Step 1. Replaced in tests (the real clone is https only; `tests/test_remote.py` covers it). With `token` (a
    private repository through Connect GitHub), a fresh shallow clone that hands git the token in its environment."""
    if not token:
        return remote.clone(link, log=log, dest=dest)
    info = remote.parse(link)
    log(f"cloning {info['url']}" + (f" (branch {info['branch']})" if info["branch"] else ""))
    remote.fetch(info["url"], dest, info["branch"], auth=token)
    left = remote.skipped(dest)
    if left:
        log(f"left out {left['files']} file(s) Lantern does not read (pictures, videos, archives, model files; "
            f"{left['mb']:,.1f} MB) to stay under the {left['cap_mb']} MB limit; the code is {left['kept_mb']:,.1f} MB")
    return dest


SAMPLE_PREFIX = "lantern:sample/"   # a run's "link" for one of Lantern's own starter apps (`lantern.learn`)
NOT_PUBLIC = ("Lantern could not open this repository: it is private, or the link is wrong. "
              "Upload your app's folder instead, and Lantern checks it the same way.")
CONNECT = ("Lantern can't read this private repository yet. Click Connect GitHub and choose it there "
           "(Lantern only reads it), or upload your app's folder instead.")
NO_ACCESS = ("Your GitHub account cannot read this repository, so Lantern won't either. "
             "If it is yours, upload your app's folder instead.")
GITHUB_ONLY = ("This repository is private. Sign in with GitHub to check private repositories, "
               "or upload your app's folder instead.")
HINTS = {NOT_PUBLIC: "upload", NO_ACCESS: "upload", GITHUB_ONLY: "upload", CONNECT: "connect"}
UPLOAD_PREFIX = "lantern:upload/"   # a run's "link" for an app uploaded as a .zip; the name is only a label


def source_name(link: str) -> str:
    """The folder name the run's code is read from. Reports name the project after its folder (the Evidence Report's
    title, "what keeps <name> safe"), so a run of github.com/owner/shop is read from a folder called `shop`, not a
    fixed `repo`. Only letters, digits, `.`, `_` and `-` are kept; anything else becomes `app`."""
    name = ""
    if is_upload(link):
        name = link[len(UPLOAD_PREFIX):]
    elif isinstance(link, str) and link.startswith(SAMPLE_PREFIX):
        name = link[len(SAMPLE_PREFIX):]
    else:
        try:
            name = remote.parse(link)["name"]
        except (ValueError, TypeError, KeyError, AttributeError):
            name = ""
    name = re.sub(r"[^\w.-]+", "-", name.rsplit("/", 1)[-1])
    name = re.sub(r"\.(git|zip)$", "", name, flags=re.I).strip(".-")[:80]
    return name or "app"


def is_upload(link: str) -> bool:
    return isinstance(link, str) and link.startswith(UPLOAD_PREFIX)


def sample_id(link: str) -> str | None:
    """The starter id of a sample run's link, or None for a repository link. Only an id Lantern ships is accepted."""
    if not isinstance(link, str) or not link.startswith(SAMPLE_PREFIX):
        return None
    sid = link[len(SAMPLE_PREFIX):]
    learn.get(sid)          # ValueError for anything that is not a shipped starter
    return sid


def get_source(link: str, dest: Path, log, access=None) -> Path:
    """Step 1: the code to read. A sample app is written from the starter templates inside the package (no network,
    nothing cloned); anything else is cloned and checked for missing files."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    sid = sample_id(link)
    if sid:
        log(f"sample app {sid}: written from Lantern's built-in starter apps (nothing downloaded)")
        learn.scaffold(sid, dest)
        return dest
    try:
        repo = clone_repo(link, dest, log)
    except RuntimeError as e:
        if not ("private" in str(e) and "could not clone" in str(e)):   # git asked for a password: private, or no such repository
            raise
        log(str(e))
        token = access() if access else None   # Connect GitHub: RuntimeError with a sentence when it cannot
        if not token:
            raise RuntimeError(NOT_PUBLIC) from None
        log("private repository: copying it with your GitHub connection (read-only)")
        try:
            repo = clone_repo(link, dest, lambda m: log(m.replace(token, "***")), token=token)
        except RuntimeError as e2:
            raise RuntimeError(str(e2).replace(token, "***")) from None
    remote.check_complete(repo)
    return repo


class Logs:
    """Per-run log lines in memory (the last 2,000), for `GET /v1/runs/{id}/stream`; the tail is saved with the run."""

    CAP = 2000
    RUNS = 200      # logs of this many recent runs are kept in memory; older runs keep their saved tail only

    def __init__(self):
        self.lines: dict[str, list[str]] = {}
        self.total: dict[str, int] = {}
        self.lock = threading.Lock()

    def add(self, rid: str, line: str) -> None:
        with self.lock:
            if rid not in self.lines and len(self.lines) >= self.RUNS:
                old = next(iter(self.lines))
                self.lines.pop(old, None)
                self.total.pop(old, None)
            lst = self.lines.setdefault(rid, [])
            lst.append(line[:500])
            if len(lst) > self.CAP:
                del lst[:len(lst) - self.CAP]
            self.total[rid] = self.total.get(rid, 0) + 1

    def since(self, rid: str, n: int) -> tuple[list[str], int]:
        """Lines numbered n and after (lines that fell off the cap are skipped), and the next number to ask for."""
        with self.lock:
            lst, total = self.lines.get(rid) or [], self.total.get(rid, 0)
            first = total - len(lst)
            return lst[max(0, n - first):], total

    def tail(self, rid: str, n: int = 40) -> str:
        with self.lock:
            return "\n".join((self.lines.get(rid) or [])[-n:])


class Worker:
    def access(self, r: dict):
        """For a github.com link: a function that returns a read-only token through Connect GitHub, or raises
        RuntimeError with the sentence to show. None when Connect GitHub is off or the host is another forge."""
        try:
            info = remote.parse(r["link"])
        except ValueError:
            return None
        if not self.github or info["host"] != "github.com" or info["port"]:
            return None

        def get() -> str:
            u = self.store.user(r["account"]) or {}
            try:
                return self.github.token_for(info["owner"], info["name"], r["account"], u.get("label"))
            except NoAccess as e:
                raise RuntimeError({"connect": CONNECT, "denied": NO_ACCESS}.get(e.kind, GITHUB_ONLY)) from None
            except (httpx.HTTPError, KeyError, ValueError):
                raise RuntimeError("GitHub did not answer Lantern's request to read this repository. "
                                   "Try again in a minute, or upload your app's folder instead.") from None
        return get

    def __init__(self, settings: Settings, store: Store):
        self.s, self.store, self.logs = settings, store, Logs()
        self.results = Path(settings.results_dir)
        self.work = Path(settings.work_dir)
        self.work.mkdir(parents=True, exist_ok=True)
        self.uploads = Path(settings.uploads())
        self.uploads.mkdir(parents=True, exist_ok=True)
        os.chmod(self.work, 0o711)   # nosec B103 - a folder: others may pass through (the analysis user, when we run as root), not list
        self.pool = ThreadPoolExecutor(max_workers=max(1, settings.concurrent_jobs), thread_name_prefix="lantern-run")
        self.tokens: dict[str, str] = {}    # run id -> allowance token, only while its explanations wait
        self.github = settings.github_app()   # Connect GitHub, or None
        self._sweep_work()
        with store.lock:   # tokens were in memory only: explanations cut off by a restart are reported, not retried
            store.db.execute("update runs set explain_status = 'error', explain_error = ? where explain_status in "
                             "('queued', 'running')", ("Lantern restarted while writing these. Click Explain again.",))
            store.db.commit()
        unfinished = store.unfinished()
        self._sweep_uploads({r["id"] for r in unfinished if r["status"] != "running"})
        for r in unfinished:   # the service restarted: queued runs go again, a half-done one is reported
            if r["status"] == "running":
                store.update_run(r["id"], status="error", stage="stopped", finished=_now(),
                                 error="Lantern restarted while this run was going. Start it again.")
            else:
                self.submit(r["id"])

    def _sweep_work(self) -> None:
        """Anything left in the work folder belongs to a run that was cut off (a crash): remove it."""
        for p in self.work.iterdir():
            sandbox._rm(p) if p.is_dir() else p.unlink(missing_ok=True)

    def _sweep_uploads(self, waiting: set[str]) -> None:
        """Keep only the uploads of runs still waiting to start; a half-received upload (`.part-*`) or one whose run
        is gone was cut off by a restart: remove it."""
        for p in self.uploads.iterdir():
            if not (p.is_file() and p.suffix == ".zip" and p.stem in waiting):
                sandbox._rm(p) if p.is_dir() else p.unlink(missing_ok=True)

    def submit(self, rid: str):
        return self.pool.submit(self.run, rid)

    def submit_explain(self, rid: str, token: str):
        self.tokens[rid] = token
        return self.pool.submit(self.explain, rid)

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ one run
    def run(self, rid: str) -> None:
        if not self.store.claim(rid):   # already taken by another thread, finished, or deleted
            return
        r = self.store.run(rid)
        root = Path(tempfile.mkdtemp(prefix="run-", dir=self.work))
        scrub = [str(root), os.path.realpath(root)]

        def log(line: str) -> None:
            for p in scrub:
                line = line.replace(p + os.sep, "").replace(p, "")
            self.logs.add(rid, line)

        def stage(key: str) -> None:
            self.store.update_run(rid, stage=STAGES[key])
            log("· " + STAGES[key])

        start = time.monotonic()
        status, error, summary, commit = "error", None, None, None
        try:
            tmp = root / "tmp"
            tmp.mkdir()
            free = shutil.disk_usage(root).free / 1_000_000
            if free < 2.5 * self.s.clone_max_mb:   # the download and its files, with room to spare
                raise RunFailed(f"Lantern's server is short of space right now ({free:,.0f} MB free). "
                                "Try again in a few minutes.")
            if is_upload(r["link"]):
                stage("unpack")
                repo = self._unpack(rid, root, log, start)
            else:
                stage("clone")
                try:
                    repo = get_source(r["link"], root / "src" / source_name(r["link"]), log, self.access(r))
                except (RuntimeError, ValueError) as e:
                    raise RunFailed(_scrub(str(e), scrub)) from None
            commit = _commit(repo)
            if commit:
                log(f"commit {commit[:12]}")
            audits = None
            if self.s.audits:
                stage("audit")
                audits = tmp / "audits.json"
                self._jailed(rid, root, [sys.executable, "-m", "lantern.depaudit", str(repo), str(audits)],
                             cwd=tmp, net=True, log=log, timeout=self._left(start))
                if not audits.is_file():
                    log("the dependency audit did not finish; the report will say so")
                    audits = None
            stage("analyze")
            out = tmp / "out"
            out.mkdir()
            # With the audit file in hand the analysis is "online" as far as the report and `lantern verify` are
            # concerned (dependencies were checked); it still has no network, and reads the audits from the file.
            cmd = self.analyze_cmd(repo, out, r["privacy"], offline=audits is None)
            rc, output, timed_out = self._jailed(rid, root, cmd, cwd=tmp, net=False, log=log,
                                                 timeout=self._left(start), audits=audits)
            blocked = sandbox.blocked_reasons(output)
            if timed_out:
                raise RunFailed(f"The analysis took longer than {self.s.job_timeout // 60} minutes and was stopped. "
                                "Very large repositories need the local app (lantern serve).")
            if blocked:
                raise RunFailed("The analysis tried something the sandbox does not allow ("
                                + "; ".join(b["what"] for b in blocked[:3]) + ") and was stopped.", "blocked")
            if rc != 0 or not (out / "report.html").is_file():
                last = [ln for ln in output.splitlines() if ln.strip() and not ln.startswith("sandbox:")][-1:]
                if last:
                    raise RunFailed("The analysis stopped with an error: " + _scrub(last[0], scrub)[:300] + ".")
                if rc is not None and rc < 0:    # killed by a signal before it could say anything: Lantern's own fault
                    raise RunFailed(f"Lantern's analysis crashed (signal {-rc}) before it could write anything. "
                                    "This is a bug on Lantern's side, not in your code.")
                raise RunFailed(f"The analysis stopped with an error (exit code {rc}) and wrote nothing.")
            stage("save")
            dest = self.results / rid
            dest.mkdir(parents=True, exist_ok=True)
            for name in RESULT_FILES:
                if (out / name).is_file():
                    shutil.copyfile(out / name, dest / name)
            summary = _summary(out)
            status = "done"
            log(f"done: {summary.get('score')}/100, {summary.get('counts')}")
        except RunFailed as e:
            status, error = e.status, str(e)
            log("stopped: " + error)
        except Exception as e:  # noqa: BLE001 - recorded, never shown with a traceback
            error = "Something went wrong on Lantern's side. The run was stopped and nothing was kept."
            log(f"internal error ({type(e).__name__})")
        finally:
            sandbox._rm(root)    # the clone and every temp file, whatever happened
            self.upload_path(rid).unlink(missing_ok=True)   # an upload never outlives its run's start
            if status != "done":
                shutil.rmtree(self.results / rid, ignore_errors=True)
            self.store.update_run(rid, status=status, error=error, summary=summary, commit_sha=commit,
                                  finished=_now(), stage="finished", log_tail=self.logs.tail(rid))

    def upload_path(self, rid: str) -> Path:
        return self.uploads / f"{rid}.zip"

    def _unpack(self, rid: str, root: Path, log, start: float) -> Path:
        """An uploaded .zip: moved into the run's temp folder, then unpacked by `lantern.archive` inside the
        restricted process (no network, writes only in the temp folder), so a hostile archive meets the same walls
        as the analysis."""
        src = self.upload_path(rid)
        if not src.is_file():
            raise RunFailed("The uploaded file is no longer here (Lantern restarted before this run began). "
                            "Upload it again.")
        tmp = root / "tmp"
        zipped = tmp / "upload.zip"
        shutil.move(str(src), zipped)
        (tmp / "src").mkdir()
        repo = tmp / "src" / source_name(self.store.run(rid)["link"])
        rc, output, timed_out = self._jailed(rid, root, [sys.executable, "-m", "lantern.archive", str(zipped), str(repo),
                                                         "--max-mb", str(self.s.clone_max_mb)],
                                             cwd=tmp, net=False, log=log, timeout=min(self._left(start), 180))
        zipped.unlink(missing_ok=True)
        if timed_out:
            raise RunFailed("Unpacking the upload took too long and was stopped.")
        if rc != 0 or not repo.is_dir():
            said = [ln for ln in output.splitlines() if ln.strip() and not ln.startswith("sandbox:")][-1:]
            raise RunFailed(said[0][:300] if said and rc == 2 else "The upload could not be unpacked.")
        return repo

    # ------------------------------------------------------------------ explanations for a finished run
    def explain(self, rid: str) -> None:
        token = self.tokens.pop(rid, None)
        if not self.store.claim_explain(rid):
            return
        r = self.store.run(rid)
        root = Path(tempfile.mkdtemp(prefix="explain-", dir=self.work))
        scrub = [str(root), os.path.realpath(root)]
        key = "x:" + rid    # its own log, so the run's saved log stays as it was

        def log(line: str) -> None:
            self.logs.add(key, _scrub(line, scrub))

        start = time.monotonic()
        status, error, summary = "error", None, None
        try:
            if not r or not token:
                raise RunFailed("Lantern restarted while these were waiting. Click Explain again.")
            if is_upload(r["link"]):
                raise RunFailed(UPLOAD_EXPLAIN)
            log("· Copying the repository again to read the code (nothing is run or installed)")
            try:
                repo = get_source(r["link"], root / "src" / source_name(r["link"]), log, self.access(r))
            except (RuntimeError, ValueError) as e:
                raise RunFailed(_scrub(str(e), scrub)) from None
            now_at = _commit(repo)
            if r["commit_sha"] and now_at and now_at != r["commit_sha"]:
                raise RunFailed("The repository has changed since this check, so its words would not match this map. "
                                "Start a new check of the link, then explain that one.")
            tmp = root / "tmp"
            out = tmp / "out"
            out.mkdir(parents=True)
            dest = self.results / rid
            for name in RESULT_FILES + ("explanations.json",):
                if (dest / name).is_file():
                    shutil.copyfile(dest / name, out / name)
            if (dest / "cache").is_dir():          # explanations already paid for are not asked for again
                shutil.copytree(dest / "cache", out / "cache")
            g = json.loads((out / "graph.json").read_text(encoding="utf-8"))
            g["repo_root"] = str(repo)             # where `explain` reads each function's source
            (out / "graph.json").write_text(json.dumps(g), encoding="utf-8")
            log("· Writing plain-words explanations with the free allowance")
            cmd = [sys.executable, "-m", "lantern.cli", "explain", str(repo), "--out", str(out), "--yes",
                   "--model", "lantern/" + _model_name(), "--max-nodes", str(EXPLAIN_MAX)]
            rc, output, timed_out = self._jailed(key, root, cmd, cwd=tmp, net=True, log=log, timeout=self._left(start),
                                                 extra={"LANTERN_TOKEN": token,
                                                        "LANTERN_GATEWAY_URL": self.s.gateway_url.rstrip("/")})
            if timed_out:
                raise RunFailed(f"Writing the explanations took longer than {self.s.job_timeout // 60} minutes and "
                                "was stopped. The ones already written are kept; click Explain again to go on.")
            ex = _read_json(out / "explanations.json")
            st = (ex or {}).get("stats") if isinstance(ex, dict) else None
            if rc != 0 or not isinstance(st, dict):
                last = [ln for ln in output.splitlines() if ln.strip() and not ln.startswith("sandbox:")][-1:]
                raise RunFailed("The explanations could not be written"
                                + (": " + _scrub(last[0], scrub)[:300] if last else "") + ".")
            for name in EXPLAINED_FILES:
                if (out / name).is_file():
                    shutil.copyfile(out / name, dest / name)
            if (out / "cache").is_dir():
                shutil.rmtree(dest / "cache", ignore_errors=True)
                shutil.copytree(out / "cache", dest / "cache")
            exps = ex.get("explanations") if isinstance(ex.get("explanations"), dict) else {}
            summary = {"functions": len(exps),
                       "validated": sum(1 for v in exps.values() if isinstance(v, dict) and v.get("validated")),
                       "failed": _int(st.get("failed")),
                       "stopped": str(st["stopped"])[:300] if st.get("stopped") else None}
            status = "done"
            log(f"done: {summary['validated']} of {summary['functions']} functions explained")
        except RunFailed as e:
            error = str(e)
            log("stopped: " + error)
        except Exception as e:  # noqa: BLE001 - recorded, never shown with a traceback
            error = "Something went wrong on Lantern's side. Nothing was changed; click Explain again."
            log(f"internal error ({type(e).__name__})")
        finally:
            sandbox._rm(root)
            self.store.update_run(rid, explain_status=status, explain_error=error, explain_summary=summary)

    @staticmethod
    def analyze_cmd(repo: Path, out: Path, privacy: str, offline: bool = True) -> list[str]:
        return [sys.executable, "-m", "lantern.cli", "analyze", str(repo), "--out", str(out), "--privacy", privacy,
                *(["--offline"] if offline else [])]

    def _left(self, start: float) -> float:
        left = self.s.job_timeout - (time.monotonic() - start)
        if left <= 5:
            raise RunFailed(f"The run used its {self.s.job_timeout // 60} minutes before the analysis could start.")
        return left

    def _jailed(self, rid, root: Path, cmd: list[str], *, cwd: Path, net: bool, log, timeout: float,
                audits: Path | None = None, extra: dict | None = None):
        """Run `cmd` in the restricted process: writes only under root/tmp, no network unless `net`."""
        tmp = root / "tmp"
        env = sandbox._env_base(tmp)
        hook = root / "hook"
        hook.mkdir(exist_ok=True)
        pkg_root = str(Path(sandbox.__file__).resolve().parent.parent)
        paths = [pkg_root]
        if not net:   # the audit hook refuses sockets and writes outside tmp, and says so in the output
            (hook / "sitecustomize.py").write_text(sandbox.SITECUSTOMIZE, encoding="utf-8")
            paths.insert(0, str(hook))
        env.update({"PYTHONPATH": os.pathsep.join(paths), "LANTERN_HOME": str(tmp / "home"),
                    "LANTERN_OFFLINE": "0" if net or audits else "1", "LANTERN_CLOUD_RUN": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": "*",
                    "LANTERN_SHARE_USAGE": "0"})
        if audits:
            env["LANTERN_AUDITS_FROM"] = str(audits)
        if net:
            env.update({k: os.environ[k] for k in PROXY_VARS if k in os.environ})
        env.update(extra or {})
        as_nobody = hasattr(os, "geteuid") and os.geteuid() == 0
        if as_nobody:   # root ignores file modes; the analysis runs as nobody, who owns only the temp folder
            for dirpath, _dirs, files in os.walk(tmp):
                os.chown(dirpath, 65534, 65534)
                for f in files:
                    os.chown(os.path.join(dirpath, f), 65534, 65534)
            os.chmod(root, 0o711)
        if os.name == "posix":
            policy = {"writable": [str(tmp)], "nobody": as_nobody, "python": True, "net": not net}
            cmd = [sys.executable, "-I", "-c",
                   f"import sys; sys.path.insert(0, {pkg_root!r}); from lantern._jail import main; main(sys.argv[1:])",
                   json.dumps(policy), "--", *cmd]
        return sandbox._stream(cmd, cwd, env, timeout, log)


def _now() -> str:
    from .store import now
    return now()


def _model_name() -> str:
    from lantern.providers import DEFAULT_MODEL_NAME
    return DEFAULT_MODEL_NAME


def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _int(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def _scrub(text: str, roots: list[str]) -> str:
    for p in roots:
        text = text.replace(p + os.sep, "").replace(p, "")
    return text


def _commit(repo: Path) -> str | None:
    try:
        r = remote._git(["rev-parse", "HEAD"], cwd=repo, timeout=30)
    except RuntimeError:
        return None
    sha = r.stdout.strip()
    return sha if r.returncode == 0 and len(sha) in (40, 64) and all(c in "0123456789abcdef" for c in sha) else None


def _summary(out: Path) -> dict:
    """Counts and score for the run list, read from the result files (facts from tools, nothing recomputed)."""
    def load(name):
        try:
            return json.loads((out / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
    rd, sec, g = load("readiness.json"), load("security.json"), load("graph.json")
    counts = sec.get("counts") if isinstance(sec.get("counts"), dict) else {}
    meta = g.get("meta") if isinstance(g.get("meta"), dict) else {}
    def num(v):
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def count(v):
        try:
            return max(0, int(v or 0))
        except (TypeError, ValueError):
            return 0
    # The result files were written by the analysis of a stranger's repository: keep only well-formed values.
    shape = rd.get("shape")
    return {"score": num(rd.get("score")), "grade": rd.get("grade") if rd.get("grade") in ("A", "B", "C", "D", "F") else None,
            "shape": shape[:80] if isinstance(shape, str) else None,
            "counts": {k: count(counts.get(k)) for k in ("critical", "high", "medium", "low")},
            "files": num(meta.get("files")), **lane_summary(sec, meta)}


LANE_KEYS = ("browser", "frontend", "server", "data")
PHONE_PLATFORMS = ("android", "ios", "flutter", "react-native", "maui")


def lane_summary(sec: dict, meta: dict) -> dict:
    """Which part of the stack the open findings sit in (security.scan's `hot_lane`), for the run list:
    {"lanes": {lane: {"critical": n, ...}}, "phone": bool}. A finding with no lane is left out, never guessed."""
    lanes = {k: {r: 0 for r in ("critical", "high", "medium", "low")} for k in LANE_KEYS}
    for f in sec.get("findings") if isinstance(sec.get("findings"), list) else []:
        if not isinstance(f, dict) or f.get("in_tests") or f.get("status") != "open":
            continue
        lane, rank = f.get("hot_lane"), f.get("rank")
        if lane in lanes and rank in lanes[lane]:
            lanes[lane][rank] += 1
    return {"lanes": lanes, "phone": meta.get("platform") in PHONE_PLATFORMS}


def backfill_lanes(results: Path, rid: str, summary: dict | None) -> dict | None:
    """A run finished before the run list showed stack parts: read them from its stored results once."""
    if not isinstance(summary, dict) or "lanes" in summary:
        return None
    def load(name):
        try:
            return json.loads((results / rid / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
    sec, g = load("security.json"), load("graph.json")
    if not isinstance(sec, dict):
        return None
    meta = g.get("meta") if isinstance(g, dict) and isinstance(g.get("meta"), dict) else {}
    return {**summary, **lane_summary(sec, meta)}
