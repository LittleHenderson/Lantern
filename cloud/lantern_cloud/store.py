"""SQLite store for cloud mode: accounts (provider id + label), runs and per-day counters.

Never stored: tokens (not even hashes; the gateway owns those), emails, request bodies, repository contents.
A run's result files live in their own folder under `Settings.results_dir`; this database holds only the row that
describes the run (link, privacy, status, timings, commit, counts).
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import sqlite3
import threading

SCHEMA = """
create table if not exists users (
  account text primary key,          -- github:<id>, google:<sub>, token:<hash prefix> (from the gateway)
  label text, created text, last_seen text);
create table if not exists runs (
  id text primary key,               -- random, unguessable
  account text not null,
  link text not null, host text, privacy text not null,
  status text not null,              -- queued | running | done | error | blocked
  stage text, error text,
  created text not null, started text, finished text,
  commit_sha text, summary text,     -- summary: JSON counts + score, written by the worker
  log_tail text,                     -- the last lines of the run's log (no tokens, no file contents)
  share_slug text unique);           -- null until the person clicks Share (off by default)
create index if not exists runs_by_account on runs (account, created);
create table if not exists daily (
  day text, account text, runs integer default 0, primary key (day, account));
create table if not exists global_daily (day text primary key, runs integer default 0);
"""

ACTIVE = ("queued", "running")
FINISHED = ("done", "error", "blocked")
RUN_FIELDS = ("id", "account", "link", "host", "privacy", "status", "stage", "error", "created", "started", "finished",
              "commit_sha", "summary", "log_tail", "share_slug")


class LimitReached(Exception):
    """Over a limit; the message is the sentence the person sees."""


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def today() -> str:
    return dt.datetime.now(dt.UTC).date().isoformat()


class Store:
    def __init__(self, path: str):
        self.lock = threading.RLock()   # one connection shared by the web server and the worker threads
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("pragma journal_mode=wal")
        self.db.executescript(SCHEMA)
        if "log_tail" not in {r[1] for r in self.db.execute("pragma table_info(runs)")}:   # a milestone-1 database
            self.db.execute("alter table runs add column log_tail text")
        self.db.commit()

    def _all(self, sql: str, args=()) -> list:
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def _one(self, sql: str, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchone()

    def touch_user(self, account: str, label: str) -> None:
        t = now()
        with self.lock:
            self.db.execute("insert into users (account, label, created, last_seen) values (?, ?, ?, ?) "
                            "on conflict(account) do update set label = excluded.label, last_seen = excluded.last_seen",
                            (account[:100], label[:100], t, t))
            self.db.commit()

    def user(self, account: str) -> dict | None:
        row = self._one("select account, label, created, last_seen from users where account = ?", (account,))
        return dict(zip(("account", "label", "created", "last_seen"), row)) if row else None

    def runs_today(self, account: str, day: str | None = None) -> int:
        row = self._one("select runs from daily where day = ? and account = ?", (day or today(), account))
        return row[0] if row else 0

    def active_runs(self, account: str | None = None) -> int:
        sql, args = "select count(*) from runs where status in (?, ?)", list(ACTIVE)
        if account is not None:
            sql += " and account = ?"
            args.append(account)
        return self._one(sql, args)[0]

    def run_ids(self, account: str) -> list[str]:
        return [r[0] for r in self._all("select id from runs where account = ?", (account,))]

    def delete_user(self, account: str) -> list[str]:
        """Forget an account: its user row, runs and counters. Returns the run ids so the caller removes their
        result folders."""
        with self.lock:
            ids = self.run_ids(account)
            self.db.execute("delete from runs where account = ?", (account,))
            self.db.execute("delete from daily where account = ?", (account,))
            self.db.execute("delete from users where account = ?", (account,))
            self.db.commit()
        return ids

    # ---- runs ----
    def create_run(self, account: str, link: str, host: str, privacy: str, *, per_day: int, global_per_day: int,
                   per_user_active: int) -> str:
        """Check the limits and create a queued run in one step (so two quick requests cannot both slip under)."""
        day = today()
        with self.lock:
            q = self.db.execute
            mine = q("select runs from daily where day = ? and account = ?", (day, account)).fetchone()
            if (mine[0] if mine else 0) >= per_day:
                raise LimitReached(f"You've used today's {per_day} runs. More are available after 00:00 UTC.")
            allr = q("select runs from global_daily where day = ?", (day,)).fetchone()
            if (allr[0] if allr else 0) >= global_per_day:
                raise LimitReached("Lantern has reached today's limit of runs for everyone. Try again after 00:00 UTC.")
            act = q("select count(*) from runs where account = ? and status in (?, ?)", (account, *ACTIVE)).fetchone()[0]
            if act >= per_user_active:
                raise LimitReached("You already have a run going. Wait for it to finish, then start the next one.")
            rid = secrets.token_urlsafe(12)
            q("insert into runs (id, account, link, host, privacy, status, stage, created) "
              "values (?, ?, ?, ?, ?, 'queued', 'waiting for a free worker', ?)", (rid, account, link[:500], host, privacy, now()))
            q("insert into daily (day, account, runs) values (?, ?, 1) "
              "on conflict(day, account) do update set runs = runs + 1", (day, account))
            q("insert into global_daily (day, runs) values (?, 1) "
              "on conflict(day) do update set runs = runs + 1", (day,))
            self.db.commit()
        return rid

    def update_run(self, rid: str, **fields) -> None:
        bad = set(fields) - set(RUN_FIELDS[4:])
        if bad:
            raise ValueError(f"not a run field: {bad}")
        if isinstance(fields.get("summary"), dict):
            fields["summary"] = json.dumps(fields["summary"])
        with self.lock:
            self.db.execute(f"update runs set {', '.join(k + ' = ?' for k in fields)} where id = ?",   # nosec B608 - names checked above
                            (*fields.values(), rid))
            self.db.commit()

    def claim(self, rid: str) -> bool:
        """queued -> running, for exactly one worker thread."""
        with self.lock:
            n = self.db.execute("update runs set status = 'running', started = ? where id = ? and status = 'queued'",
                                (now(), rid)).rowcount
            self.db.commit()
        return n == 1

    def run(self, rid: str) -> dict | None:
        row = self._one(f"select {', '.join(RUN_FIELDS)} from runs where id = ?", (rid,))   # nosec B608
        return self._run_dict(row) if row else None

    def runs(self, account: str, limit: int = 100) -> list[dict]:
        rows = self._all(f"select {', '.join(RUN_FIELDS)} from runs where account = ? "   # nosec B608
                         "order by created desc limit ?", (account, limit))
        return [self._run_dict(r) for r in rows]

    def unfinished(self) -> list[dict]:
        rows = self._all(f"select {', '.join(RUN_FIELDS)} from runs where status in (?, ?) "   # nosec B608
                         "order by created", ACTIVE)
        return [self._run_dict(r) for r in rows]

    @staticmethod
    def _run_dict(row) -> dict:
        d = dict(zip(RUN_FIELDS, row))
        try:
            d["summary"] = json.loads(d["summary"]) if d["summary"] else None
        except ValueError:
            d["summary"] = None
        return d

    def stats(self) -> dict:
        """Aggregates for the owner. No links, no labels."""
        by_status = {s: n for s, n in self._all("select status, count(*) from runs group by status")}
        g = self._one("select runs from global_daily where day = ?", (today(),))
        return {"users": self._one("select count(*) from users")[0],
                "runs": sum(by_status.values()), "runs_by_status": by_status, "runs_today": g[0] if g else 0,
                "shared": self._one("select count(*) from runs where share_slug is not null")[0]}
