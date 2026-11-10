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
  4. The result files are copied to the run's folder; the temp folder (clone included) is removed in `finally`,
     through `cleanup.Cleanup`: when that cannot be done it is written down, said in the run's log and tried again,
     and the run is recorded as ended either way.

Plain-words explanations (`explain`, when the owner asks and has agreed to send code to the model): the clone is
gone by then, so the repository is copied again at the run's commit (a different commit is refused, so the words
match the map), `lantern explain` runs in the restricted process with the network on (it talks to the gateway with
the person's own allowance token, passed in the environment and held only in memory while the job waits), the new
explanations and the rebuilt report are copied back, and the copy is deleted again.

The analysed code is never executed: no builds, installs, tests or tracing. This is the same reason the local app
can analyse a stranger's repository; the sandbox is a second wall in case the analyser itself is tricked.
"""

from __future__ import annotations

import contextlib
import errno
import json
import logging
import os
import re
import shutil
import stat
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import httpx

from lantern import _jail, gitfacts, learn, remote, removal, sandbox

from .cleanup import Cleanup
from .ghapp import NoAccess
from .settings import Settings
from .store import Store

_log = logging.getLogger("lantern_cloud")
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
# What a person is told when a step left something other than a plain file where a result belongs (a link, a
# folder, a device). Lantern's own steps never do; nothing of such a step is kept.
NOT_PLAIN = ("Lantern's own step left something that is not a plain file where a result belongs, so nothing of it "
             "was kept. This is a problem on Lantern's side, not in your code.")
# The line a run's log gets when its work folder could not be removed at its end. It never says where the folder is.
NOT_REMOVED = ("Lantern could not remove its copy of the code from its server yet. It has written that down and "
               "tries again by itself; the owner is told when that takes more than a day.")
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy",
              "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS")


SHUT_DOWN = "Lantern was shut down while this run was going. Start it again."
SHUT_DOWN_EXPLAIN = "Lantern was shut down while writing these. Click Explain again."
UPLOAD_EXPLAIN = ("An uploaded app is deleted when its check ends, so Lantern cannot read its code again to explain it. "
                  "Explanations work for apps checked from a link, or in the Lantern app on your computer.")


class RunFailed(Exception):
    """A plain sentence for the person, and the status to record (`error` or `blocked`)."""

    def __init__(self, message: str, status: str = "error"):
        super().__init__(message)
        self.status = status


class ShutDown(RunFailed):
    """The service is stopping (`Worker.shutdown`): the step was ended, with everything it had started."""

    def __init__(self):
        super().__init__(SHUT_DOWN)


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

    def __init__(self, settings: Settings, store: Store, cleanup: Cleanup | None = None):
        self.s, self.store, self.logs = settings, store, Logs()
        self.results = Path(settings.results_dir)
        self.work = Path(settings.work_dir)
        self.work.mkdir(parents=True, exist_ok=True)
        self.uploads = Path(settings.uploads())
        self.uploads.mkdir(parents=True, exist_ok=True)
        os.chmod(self.work, 0o711)   # nosec B103 - a folder: others may pass through (the analysis user, when we run as root), not list
        self.pool = ThreadPoolExecutor(max_workers=max(1, settings.concurrent_jobs), thread_name_prefix="lantern-run")
        self.stopping = threading.Event()   # shutdown(): the steps that are running end, with all they started
        self.tokens: dict[str, str] = {}    # run id -> allowance token, only while its explanations wait
        self.github = settings.github_app()   # Connect GitHub, or None
        # Everything this service deletes goes through here (`cleanup.py`): only what it made, written down first.
        self.cleanup = cleanup or Cleanup(store, self.results, self.work, self.uploads, days=settings.retention_days)
        self._sweep(self.cleanup.sweep_work)
        with store.lock:   # tokens were in memory only: explanations cut off by a restart are reported, not retried
            store.db.execute("update runs set explain_status = 'error', explain_error = ? where explain_status in "
                             "('queued', 'running')", ("Lantern restarted while writing these. Click Explain again.",))
            store.db.commit()
        unfinished = store.unfinished()
        self._sweep(self.cleanup.sweep_uploads, {r["id"] for r in unfinished if r["status"] != "running"})
        for r in unfinished:   # the service restarted: queued runs go again, a half-done one is reported
            if r["status"] == "running":
                store.update_run(r["id"], status="error", stage="stopped", finished=_now(),
                                 error="Lantern restarted while this run was going. Start it again.")
            else:
                self.submit(r["id"])

    @staticmethod
    def _sweep(sweep, *args) -> None:
        """A start-up sweep: what the runs a restart cut off left behind (`Cleanup.sweep_work`, `sweep_uploads`:
        only what the service itself made; until 2026-11-10 everything in both folders was deleted, whatever it
        was). A sweep that breaks is logged and never keeps the service from starting: until then a work folder
        nested 1,100 deep did, on Python 3.11 and 3.12."""
        try:
            sweep(*args)
        except Exception as e:  # noqa: BLE001
            _log.warning("clean-up at start-up failed (%s); the next pass tries again", type(e).__name__)

    def submit(self, rid: str):
        return self.pool.submit(self.run, rid)

    def submit_explain(self, rid: str, token: str):
        self.tokens[rid] = token
        return self.pool.submit(self.explain, rid)

    def shutdown(self) -> None:
        """No new run starts, and a step that is running is ended with everything it started. (When the service
        itself is killed, the launcher of each step is told by the kernel and does the same: `lantern._jail`.)"""
        self.stopping.set()
        self.pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ one run
    def run(self, rid: str) -> None:
        if not self.store.claim(rid):   # already taken by another thread, finished, or deleted
            return
        root: Path | None = None
        scrub: list[str] = []           # the run's folder, once it is made: never shown in the log

        def log(line: str) -> None:
            for p in scrub:
                line = line.replace(p + os.sep, "").replace(p, "")
            self.logs.add(rid, line)

        def stage(key: str) -> None:
            self.store.update_run(rid, stage=STAGES[key])
            log("· " + STAGES[key])

        start = time.monotonic()
        status, error, summary, commit = "error", None, None, None
        try:    # from the claim to the record at the end, everything is in here: a run that began is recorded as ended
            r = self.store.run(rid)
            root = self.cleanup.fresh("run-")
            scrub += [str(root), os.path.realpath(root)]
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
            # From here on the step's folder is read by the service itself, which has more rights than the step had:
            # nothing in it is followed (`_there`, `_take`).
            try:
                if rc != 0 or not _there(out, "report.html"):
                    last = [ln for ln in output.splitlines() if ln.strip() and not ln.startswith("sandbox:")][-1:]
                    if last:
                        raise RunFailed("The analysis stopped with an error: " + _scrub(last[0], scrub)[:300] + ".")
                    if rc is not None and rc < 0:    # killed by a signal before it could say anything: Lantern's fault
                        raise RunFailed(f"Lantern's analysis crashed (signal {-rc}) before it could write anything. "
                                        "This is a bug on Lantern's side, not in your code.")
                    raise RunFailed(f"The analysis stopped with an error (exit code {rc}) and wrote nothing.")
                stage("save")
                dest = self.results / rid
                dest.mkdir(parents=True, exist_ok=True)
                _take(out, RESULT_FILES, dest)
            except NotPlain:
                raise RunFailed(NOT_PLAIN) from None
            summary = _summary(dest)       # read from the copies: plain files in the service's own folder
            status = "done"
            log(f"done: {summary.get('score')}/100, {summary.get('counts')}")
        except RunFailed as e:
            status, error = e.status, str(e)
            log("stopped: " + error)
        except Exception as e:  # noqa: BLE001 - recorded, never shown with a traceback
            error = "Something went wrong on Lantern's side. The run was stopped and nothing was kept."
            log(f"internal error ({type(e).__name__})")
        finally:
            # The clone and every temp file, whatever happened; the upload, which never outlives its run's start;
            # and, when the run did not finish, the results it had begun to write. Then the record, always: until
            # 2026-11-10 a folder that could not be deleted raised here, before the record. The run then stayed
            # "running" for good and its owner could not start another.
            try:
                self._tidy(root, [("upload", f"{rid}.zip")] + ([] if status == "done" else [("results", rid)]), log)
            finally:
                self.store.update_run(rid, status=status, error=error, summary=summary, commit_sha=commit,
                                      finished=_now(), stage="finished", log_tail=self.logs.tail(rid))

    def _tidy(self, root: Path | None, also: list[tuple[str, str]], log) -> None:
        """What a run or an explanation leaves when it ends: its work folder, and whatever else it owes. Never
        raises. What could not be removed is written down (`Cleanup.discard`) and tried again by the next pass; the
        log says so when it is the copy of the code, and never says where that is."""
        for kind, name in ([("work", root.name)] if root is not None else []) + also:
            try:
                gone = self.cleanup.discard(kind, name)
            except Exception as e:  # noqa: BLE001 - the run still has to be recorded as ended
                gone = False
                _log.warning("clean-up after a run failed (%s); written down for the next pass", type(e).__name__)
                with contextlib.suppress(Exception):
                    if kind == "work":
                        self.cleanup.release(name)
                    self.store.note_leftover(kind, name)
            if not gone and kind == "work":
                log(NOT_REMOVED)

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
        root: Path | None = None
        scrub: list[str] = []
        key = "x:" + rid    # its own log, so the run's saved log stays as it was

        def log(line: str) -> None:
            self.logs.add(key, _scrub(line, scrub))

        start = time.monotonic()
        status, error, summary = "error", None, None
        try:
            r = self.store.run(rid)
            root = self.cleanup.fresh("explain-")
            scrub += [str(root), os.path.realpath(root)]
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
                # Each explanation is saved in the cache folder as it is written, and it has been paid for from the
                # person's allowance: those files are kept with the run, so the next click goes on from there. (Until
                # 2026-11-10 the sentence below was said and they were thrown away with the work folder.)
                try:
                    kept = _take_tree(out, "cache", dest / "cache") > 0
                except (NotPlain, OSError):
                    kept = False
                raise RunFailed(f"Writing the explanations took longer than {self.s.job_timeout // 60} minutes and "
                                "was stopped. " + ("The ones already written are kept; click Explain again to go on."
                                                   if kept else "Click Explain again."))
            # Saved so that "nothing was changed" below is true when a step fails. What the step wrote is taken
            # without following a link (`_take`; a link among it, and nothing of the step is kept). Every rewritten
            # file is first written beside its old one and the stats are read from that copy; then the cache, into
            # the folder that is there (until 2026-11-10 the old one was deleted to make room, any failure of that
            # unsaid, after the new pages were already in place); and only then is each page put in its old one's
            # place.
            try:
                try:
                    staged = _take(out, EXPLAINED_FILES, dest, as_name=".{}.new")
                    ex = _read_json(dest / ".explanations.json.new") if "explanations.json" in staged else None
                    st = (ex or {}).get("stats") if isinstance(ex, dict) else None
                    if rc != 0 or not isinstance(st, dict):
                        last = [ln for ln in output.splitlines() if ln.strip() and not ln.startswith("sandbox:")][-1:]
                        raise RunFailed("The explanations could not be written"
                                        + (": " + _scrub(last[0], scrub)[:300] if last else "") + ".")
                    _take_tree(out, "cache", dest / "cache")
                except NotPlain:
                    raise RunFailed(NOT_PLAIN.replace("so nothing of it was kept", "so nothing was changed")) from None
                for name in staged:
                    os.replace(dest / f".{name}.new", dest / name)
            finally:    # nothing half-written stays beside the results (after a save that worked, none is there)
                if [n for n in EXPLAINED_FILES if removal.remove(dest / f".{n}.new") is not None]:
                    log("a page that was only half written could not be removed; it goes with this check's results")
            exps = ex.get("explanations") if isinstance(ex.get("explanations"), dict) else {}
            summary = {"functions": len(exps),
                       "validated": sum(1 for v in exps.values() if isinstance(v, dict) and v.get("validated")),
                       "failed": _int(st.get("failed")),
                       "stopped": str(st["stopped"])[:300] if st.get("stopped") else None}
            status = "done"
            log(f"done: {summary['validated']} of {summary['functions']} functions explained")
        except RunFailed as e:
            error = SHUT_DOWN_EXPLAIN if isinstance(e, ShutDown) else str(e)
            log("stopped: " + error)
        except Exception as e:  # noqa: BLE001 - recorded, never shown with a traceback
            error = "Something went wrong on Lantern's side. Nothing was changed; click Explain again."
            log(f"internal error ({type(e).__name__})")
        finally:
            try:
                self._tidy(root, [], log)
            finally:
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
        """Run `cmd` in the restricted process: writes only under root/tmp, no network unless `net`. `ShutDown`
        when the service is stopping: the step is then not started, or ended with everything it had started."""
        if self.stopping.is_set():
            raise ShutDown()
        tmp = root / "tmp"
        env = sandbox._env_base(tmp)
        hook = root / "hook"
        hook.mkdir(exist_ok=True)
        pkg_root = str(Path(sandbox.__file__).resolve().parent.parent)
        paths = [pkg_root]
        if not net:   # the audit hook refuses sockets and writes outside tmp, and says so in the output
            (hook / "sitecustomize.py").write_text(sandbox.SITECUSTOMIZE, encoding="utf-8")
            paths.insert(0, str(hook))
            env["LANTERN_SANDBOX_GUARD"] = "expected"   # the step says so in the log when it is not in its Python
        env.update({"PYTHONPATH": os.pathsep.join(paths), "LANTERN_HOME": str(tmp / "home"),
                    "LANTERN_OFFLINE": "0" if net or audits else "1", "LANTERN_CLOUD_RUN": "1", "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
                    "LANTERN_SHARE_USAGE": "0"})
        # Until 2026-11-10 the step was also told `safe.directory=*`, so that git, started in a folder that belongs
        # to another user, would answer. No step starts git in the project's folder any more (`lantern.gitfacts`).
        # Where the step runs as another user than the folder's owner (the service as root), git's own refusal
        # there is a second wall should some code do it again; where both are one user, it is not.
        # A step looks for the project's git folder in the folder it was given and no higher (git's own variable,
        # which `lantern.gitfacts` keeps): the two places a run's code is put, a clone's and an upload's. Until
        # that day a `.git` above the service's work folder gave its commit to an upload that had none.
        env["GIT_CEILING_DIRECTORIES"] = os.pathsep.join([str(root / "src"), str(tmp / "src")])
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
            if not net:   # where root's files are made owner-only (umask 077) the step ran with no guard, unsaid
                sandbox._others_may_read(hook)
        if os.name == "posix":
            # no "must": these steps read a project and never run it, so where the kernel has no Landlock, or
            # refuses it, they say so in the log and carry on (lantern/_jail.py). "parent": a launcher whose service
            # is gone does not start its step, and one whose service ends, ends its step.
            policy = {"writable": [str(tmp)], "nobody": as_nobody, "python": True, "net": not net, "parent": os.getpid()}
            cmd = [sys.executable, "-I", "-c",
                   f"import sys; sys.path.insert(0, {pkg_root!r}); from lantern._jail import main; main(sys.argv[1:])",
                   json.dumps(policy), "--", *cmd]
        rc, output, timed_out = sandbox._stream(cmd, cwd, env, timeout, log, cancel=self.stopping,
                                                ask=_jail.ASK if sandbox._LINUX else 0.0)
        if rc is None and not timed_out:
            raise ShutDown()
        return rc, output, timed_out


def _now() -> str:
    from .store import now
    return now()


def _model_name() -> str:
    from lantern.providers import DEFAULT_MODEL_NAME
    return DEFAULT_MODEL_NAME


class NotPlain(Exception):
    """Something a restricted step left where a result belongs is not a plain file of its own or a real folder."""


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
MAX_CACHE_DEPTH = 8      # the explain cache is one folder of files; anything nested deeper is not Lantern's


def _folder(name, dir_fd: int | None = None) -> int | None:
    """Open a real folder (never a link to one). None when nothing is there."""
    try:
        return os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | _NOFOLLOW, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
            raise NotPlain() from None
        raise


def _own_file(st: os.stat_result) -> bool:
    """A plain file with one name. A file that has a second name somewhere (a hard link) may be somebody else's
    file, which the step could name and the service can read; a file the step wrote has one."""
    return stat.S_ISREG(st.st_mode) and st.st_nlink <= 1


def _there(out: Path, name: str) -> bool:
    """Whether the folder `out` holds something called `name`, a file or not. Nothing is followed: the folder is
    opened only as a real folder (`NotPlain` when it is a link), and the name is looked at, never opened."""
    fd = _folder(out)
    if fd is None:
        return False
    try:
        os.stat(name, dir_fd=fd, follow_symlinks=False)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def _take_one(fd: int, name: str, dst: Path) -> bool:
    """Copy the plain file `name` of the folder held open as `fd` to `dst`. False when there is no such file."""
    try:
        f = os.open(name, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | _NOFOLLOW, dir_fd=fd)
    except FileNotFoundError:
        return False
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise NotPlain() from None
        raise
    try:
        if not _own_file(os.fstat(f)):     # asked of what is open, not of its name (a folder or a pipe opens too)
            raise NotPlain()
        src = os.fdopen(f, "rb")
    except BaseException:
        os.close(f)
        raise
    with src, open(dst, "wb") as to:
        shutil.copyfileobj(src, to)
    return True


def _take(out: Path, names, dest: Path, as_name: str = "{}") -> list[str]:
    """Copy the files `names` that a restricted step wrote in `out` into `dest`, a folder of the service's, and
    return the ones that were there. Only plain files are taken, reached from the folder itself held open: neither
    `out` nor a file in it is followed when it is a link, and a file with a second name elsewhere is not read. The
    step runs with fewer rights than the service, which would otherwise read the link's target for it and keep the
    copy where the run's owner can download it (until 2026-11-10: `shutil.copyfile` after `is_file()`, both of
    which follow links). `NotPlain` for a link, a folder or a device where a file belongs; the step has ended by now
    (`_jailed`), so nothing changes under the copy."""
    fd = _folder(out)
    if fd is None:
        return []
    try:
        return [n for n in names if _take_one(fd, n, dest / as_name.format(n))]
    finally:
        os.close(fd)


def _take_tree(out: Path, name: str, dest: Path) -> int:
    """Copy the folder `name` of `out` (the explain cache) into `dest`, adding to what is there, and return how many
    files that was: plain files and real folders only, each reached from its folder held open. `NotPlain` for
    anything else, looked for in the whole tree before the first file is copied. Each file arrives whole or not at
    all: it is written beside its place and then put there, so a copy that stops half-way (a full disk) leaves the
    explanation that was kept before as it was."""
    top = _folder(out)
    if top is None:
        return 0
    try:
        fd = _folder(name, dir_fd=top)
    finally:
        os.close(top)
    if fd is None:
        return 0

    def walk(fd: int, into: Path | None, depth: int) -> int:
        if depth > MAX_CACHE_DEPTH:
            raise NotPlain()
        with os.scandir(fd) as it:
            entries = [e.name for e in it]
        n = 0
        for entry in entries:
            st = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                sub = _folder(entry, dir_fd=fd)
                if sub is None:
                    continue
                try:
                    if into is not None:
                        (into / entry).mkdir(exist_ok=True)
                    n += walk(sub, into / entry if into is not None else None, depth + 1)
                finally:
                    os.close(sub)
            elif not _own_file(st):
                raise NotPlain()
            elif into is not None:       # (the first pass, with `into` None, only looks)
                part = into / f".{entry}.part"
                try:
                    if _take_one(fd, entry, part):
                        os.replace(part, into / entry)
                        n += 1
                finally:
                    with contextlib.suppress(OSError):
                        os.unlink(part)             # there only when the copy stopped half-way
        return n
    try:
        walk(fd, None, 0)
        dest.mkdir(parents=True, exist_ok=True)
        return walk(fd, dest, 0)
    finally:
        os.close(fd)


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
    """The commit the code is at, read by hand (`gitfacts.head_commit`) from a git folder that lies in the run's
    code itself, and from nowhere else: not from a folder above it and not from a place its `.git` names. What is
    outside a run's code is the service's, not the project's. No program is started, whatever the folder holds:
    this runs in the service itself, outside the restricted step, and an uploaded folder brings its own `.git`,
    whose settings git would obey."""
    return gitfacts.head_commit(repo, alone=True)


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
