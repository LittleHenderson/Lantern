"""What the cloud service deletes, and what it does when a delete fails (2026-11-10, stage 7 of the 2026-11-09
directive: "Fix silent report-retention cleanup failures. Record and safely retry failed cleanup without deleting
user-owned source folders. Test path, link and ownership boundaries.").

The service keeps three folders, and deletes only what it made itself in each:
  results   one folder per run, named by the run's id; deleted when the person deletes the run or their account,
            when the run is older than the retention time, or when the run did not finish;
  work      one folder per run that is going (`run-…`, `explain-…`), with the service's mark in it (`MARK`);
            deleted when the run ends, and at start-up when a restart cut the run off;
  uploads   one `<run id>.zip` per uploaded app waiting for its run, and `.part-…` while one is being received.

Until this change every delete was silent: `shutil.rmtree(..., ignore_errors=True)` and `unlink(missing_ok=True)`.
A person was told "deleted" while the files stayed, nothing was written down and nothing tried again; and at
start-up the service emptied the work and uploads folders whatever was in them.

Now one function removes (`Cleanup.discard`, through `lantern.removal`: never through a link, any depth, no mode
changed outside the folder) and three rules hold.
  * Written down first. Before a removal starts, the store has a row for it (`leftovers`: kind + name; for a
    deleted run the row is made in the same step as the delete, `Store.delete_run`). The row goes when nothing is
    left on the disk. So a delete that failed, or that a restart cut off, is finished by the next pass.
  * Only names, never paths. A row holds one of three kinds and one name of the shape Lantern gives. A name of any
    other shape, a path, a link, a file where a folder belongs, another user's folder: nothing is removed. A
    finished run that is still listed is never a leftover, and neither is the upload of a run still waiting.
  * Said. The person's delete answers `"files": "removed"` or `"waiting"`; a run's log says when its copy of the
    code could not be removed; the owner's statistics give counts, reasons and the last pass; and `/v1/health` says
    `cleanup: behind` once something has been owed for a day, which the uptime check turns into an email.

What the service did not make is left exactly as it is and counted for the owner (`left_alone`): anything in the
work folder without the mark, anything in the uploads folder that is not a run's, and result folders no run points
at (a failed delete before this change left those; the owner decides).

Tests: tests/test_cloud_cleanup.py.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import logging
import os
import re
import stat
import tempfile
import threading
from pathlib import Path

from lantern import removal

log = logging.getLogger("lantern_cloud")
MARK = ".lantern-work"                               # in every folder `fresh` makes: "the service made this"
MARK_TEXT = "made by lantern-cloud for one run\n"
RUN_ID = re.compile(r"[A-Za-z0-9_-]{16}")            # what `Store.create_run` gives: secrets.token_urlsafe(12)
WORK = re.compile(r"(?:run|explain)-[a-z0-9_]{8}")   # what tempfile.mkdtemp(prefix="run-" | "explain-") names
PART = re.compile(r"\.part-[0-9a-f]{16}")            # an upload while it is received (`app.upload_run`)
UPLOAD = re.compile(r"\.part-[0-9a-f]{16}|[A-Za-z0-9_-]{16}\.zip")
KINDS = ("results", "work", "upload")
BEHIND_HOURS = 24                                    # owed this long: `/v1/health` says "behind"
HOUR, SOON = 3600.0, 300.0                           # between passes; and after a pass that failed


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _older(when, hours: float, now: dt.datetime) -> bool:
    """Whether the time written as `when` is `hours` or more before `now`. A time that cannot be read counts as
    old: the owner is told, and looks."""
    try:
        t = dt.datetime.fromisoformat(when)
    except (TypeError, ValueError):
        return True
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.UTC)
    return (now - t).total_seconds() >= hours * 3600


class Cleanup:
    """The one place the cloud service deletes from. `days`: the retention time (0: results are kept until the
    person deletes them); `retention`: what a pass calls to remove the runs older than that (`app.sweep`)."""

    def __init__(self, store, results, work=None, uploads=None, days: int = 0, retention=None):
        self.store = store
        self.results = Path(results)
        self.work = Path(work) if work else None
        self.uploads = Path(uploads) if uploads else None
        self.days, self.retention = days, retention
        self.first = threading.Event()               # the first pass has ended
        self.refused = 0                             # records that named nothing Lantern removes (thrown away)
        self._live: set[str] = set()                 # work folders of the runs going on now
        self._busy: set[tuple[str, str]] = set()     # what is being removed this moment
        self._lock = threading.Lock()
        self._free = threading.Condition(self._lock)
        self._one_pass = threading.Lock()
        self._left = {"work": 0, "uploads": 0, "results": 0}
        self._last: dict = {"at": None, "ok": None, "error": None, "removed": 0}

    # ------------------------------------------------------------------ one thing
    def _place(self, kind) -> tuple[Path, re.Pattern, str] | None:
        if kind == "results":
            return self.results, RUN_ID, "folder"
        if kind == "work" and self.work is not None:
            return self.work, WORK, "folder"
        if kind == "upload" and self.uploads is not None:
            return self.uploads, UPLOAD, "file"
        return None

    @contextlib.contextmanager
    def _turn(self, key: tuple[str, str]):
        """One removal of a thing at a time (a person's delete and the pass's second try can meet)."""
        with self._free:
            while key in self._busy:
                self._free.wait()
            self._busy.add(key)
        try:
            yield
        finally:
            with self._free:
                self._busy.discard(key)
                self._free.notify_all()

    def _in_use(self, kind: str, name: str) -> bool:
        """Results of a finished run that is still listed, or the upload of a run that has not started: never a
        leftover, whatever a record says."""
        if kind == "results":
            r = self.store.run(name)
            return bool(r) and r["status"] == "done"
        if kind == "upload" and name.endswith(".zip"):
            r = self.store.run(name[:-4])
            return bool(r) and r["status"] == "queued"
        return False

    def _refuse(self, kind, name) -> bool:
        with self._lock:
            self.refused += 1
        if isinstance(kind, str) and isinstance(name, str):
            self.store.forget_leftover(kind, name)
        return False

    def discard(self, kind: str, name: str) -> bool:
        """Remove one thing the service made: `name` in the folder for `kind` ("results", "work", "upload").
        True: nothing is there (any more). False: it is still there, which is then written down with the reason
        and tried again by the next pass; or it is not something the service removes (a name of another shape, a
        finished run that is still listed), and then nothing is written down. Never raises for what the system
        refused."""
        place = self._place(kind) if isinstance(kind, str) else None
        if place is None or not isinstance(name, str):
            return self._refuse(kind, name)
        holder, shape, what = place
        if kind == "work":
            self.release(name)                       # the caller says its run is over
        with self._turn((kind, name)):
            verdict = removal.ours(holder, name, shape, what)
            if verdict == "name" or self._in_use(kind, name):
                return self._refuse(kind, name)
            if verdict == "gone":
                self.store.forget_leftover(kind, name)
                return True
            self.store.note_leftover(kind, name)     # first: a service cut off in the middle finishes it later
            why = removal.WHY[verdict] if verdict else removal.remove(holder / name)
            if why is None:
                self.store.forget_leftover(kind, name)
                return True
            self.store.leftover_failed(kind, name, why)
            return False

    # ------------------------------------------------------------------ the work folder
    def fresh(self, prefix: str) -> Path:
        """A new folder in the work folder for one run, holding the service's mark. The mark is what tells a
        start-up sweep that the folder is the service's own and not something a person put there."""
        if self.work is None:
            raise RuntimeError("no work folder")
        with self._lock:                             # a count never sees the folder before its mark is in it
            root = Path(tempfile.mkdtemp(prefix=prefix, dir=self.work))
            try:
                with open(root / MARK, "x", encoding="utf-8") as f:
                    f.write(MARK_TEXT)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.rmdir(root)                   # empty, and made a moment ago by this very call
                raise
            self._live.add(root.name)
        return root

    def release(self, name: str) -> None:
        """The run that had this work folder is over: from now on a pass may remove what is left of it."""
        with self._lock:
            self._live.discard(name)

    def _marked(self, name: str) -> bool:
        try:
            return stat.S_ISREG(os.lstat(self.work / name / MARK).st_mode)
        except (OSError, ValueError):
            return False

    @staticmethod
    def _names(folder: Path | None) -> list[str]:
        try:
            return sorted(os.listdir(folder)) if folder is not None else []
        except OSError:
            return []

    def sweep_work(self) -> int:
        """At start-up: remove what the runs a restart cut off left in the work folder. Only a real folder with a
        run folder's name, owned by the user the service runs as, holding the mark. Anything else there was not made
        by the service: it is left exactly as it is and counted. Returns how many were removed."""
        removed = 0
        for name in self._names(self.work):
            if removal.ours(self.work, name, WORK) is None and self._marked(name):
                removed += bool(self.discard("work", name))
        self._count("work")
        return removed

    def sweep_uploads(self, waiting: set[str]) -> int:
        """At start-up: remove an upload that was cut off while it was received (`.part-…`), and the upload of a run
        that is over. The upload of a run still `waiting` to start is kept for it. Anything else there (a .zip no
        run has the id of, a folder, a link) was not made by the service: left as it is and counted."""
        removed = 0
        known = self.store.all_run_ids()
        for name in self._names(self.uploads):
            if removal.ours(self.uploads, name, UPLOAD, "file") is not None:
                continue
            if PART.fullmatch(name) or (name[:-4] in known and name[:-4] not in waiting):
                removed += bool(self.discard("upload", name))
        self._count("uploads")
        return removed

    # ------------------------------------------------------------------ the pass
    def _count(self, which: str) -> None:
        """How many things in one of the three folders are not the service's own. They are never removed; the owner
        is given the number. What is written down as still to be removed is counted there, not here."""
        owed = {(r["kind"], r["name"]) for r in self.store.leftovers()}
        n = 0
        if which == "work":
            with self._lock:                         # not while `fresh` is between making a folder and marking it
                for name in self._names(self.work):
                    mine = name in self._live or (removal.ours(self.work, name, WORK) is None and self._marked(name))
                    n += not (mine or ("work", name) in owed)
                self._left[which] = n
            return
        elif which == "uploads":
            known = self.store.all_run_ids()
            for name in self._names(self.uploads):
                mine = (removal.ours(self.uploads, name, UPLOAD, "file") is None
                        and (bool(PART.fullmatch(name)) or name[:-4] in known))
                n += not (mine or ("upload", name) in owed)
        else:
            known = self.store.all_run_ids()
            for name in self._names(self.results):
                mine = name in known and removal.ours(self.results, name, RUN_ID) is None
                n += not (mine or ("results", name) in owed)
        with self._lock:
            self._left[which] = n

    def retry(self) -> int:
        """Try again everything written down as still to be removed. Returns how many of them are gone now."""
        gone = 0
        for row in self.store.leftovers():
            kind, name = row["kind"], row["name"]
            with self._lock:
                going = kind == "work" and name in self._live
            if not going:                            # a run that is still going removes its own folder when it ends
                gone += bool(self.discard(kind, name))
        return gone

    def upkeep(self) -> dict:
        """One pass: the runs past the retention time (when one is set), a second try for everything written down,
        and a new count of what is not the service's. A step that breaks does not stop the others, and the pass
        never raises: what happened is kept for the owner (`state()["last_pass"]`)."""
        with self._one_pass:
            error, removed = None, 0
            steps: list = []
            if self.days > 0 and self.retention is not None:
                steps.append(("retention", self.retention))
            steps.append(("retry", self.retry))
            steps += [("count", lambda w=w: self._count(w)) for w in ("work", "uploads", "results")]
            for what, step in steps:
                try:
                    got = step()
                    if what == "retry":
                        removed = got
                except Exception as e:  # noqa: BLE001 - kept for the owner; the next pass tries again
                    error = error or type(e).__name__
                    log.warning("clean-up: the %s step failed (%s)", what, type(e).__name__)
            with self._lock:
                self._last = {"at": _now().isoformat(), "ok": error is None, "error": error, "removed": removed}
                last = dict(self._last)
            self.first.set()
            return last

    def run_forever(self, stop: threading.Event) -> None:
        """A pass now, then one an hour (five minutes after a pass that failed), until `stop` is set."""
        while not stop.is_set():
            stop.wait(HOUR if self.upkeep()["ok"] else SOON)

    # ------------------------------------------------------------------ what the owner sees
    def behind(self) -> bool:
        """Something has been waiting to be removed for a day or more, or a run is still listed a day after the
        retention time said it should be gone."""
        now = _now()
        oldest = self.store.oldest_leftover()
        if oldest is not None and _older(oldest, BEHIND_HOURS, now):
            return True
        if self.days > 0:
            ended = self.store.oldest_finished()
            if ended is not None and _older(ended, (self.days + 1) * 24, now):
                return True
        return False

    def state(self) -> dict:
        """Counts and reasons for the owner. No run id, no file name, no path."""
        rows = self.store.leftovers()
        by_kind: dict[str, int] = {}
        for r in rows:
            if r["kind"] in KINDS:
                by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        reasons: list[str] = []
        for r in rows:
            why = (r["why"] or "")[:200] if isinstance(r["why"], str) else ""
            if why and why not in reasons and len(reasons) < 5:
                reasons.append(why)
        with self._lock:
            left, last, refused = dict(self._left), dict(self._last), self.refused
        return {"waiting": len(rows), "by_kind": by_kind, "oldest": min((r["noted"] for r in rows), default=None),
                "reasons": reasons, "left_alone": left, "last_pass": last, "behind": self.behind(), "refused": refused}
