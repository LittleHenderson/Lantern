"""SQLite store for cloud mode: accounts (provider id + label), runs and per-day counters.

Never stored: tokens (not even hashes; the gateway owns those), emails, request bodies, repository contents.
A run's result files live in their own folder under `Settings.results_dir`; this database holds only the row that
describes the run (link, privacy, status, timings, commit, counts).
"""

from __future__ import annotations

import datetime as dt
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
  share_slug text unique);           -- null until the person clicks Share (off by default)
create index if not exists runs_by_account on runs (account, created);
create table if not exists daily (
  day text, account text, runs integer default 0, primary key (day, account));
create table if not exists global_daily (day text primary key, runs integer default 0);
"""

ACTIVE = ("queued", "running")


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def today() -> str:
    return dt.datetime.now(dt.UTC).date().isoformat()


class Store:
    def __init__(self, path: str):
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("pragma journal_mode=wal")
        self.db.executescript(SCHEMA)
        self.db.commit()

    def touch_user(self, account: str, label: str) -> None:
        t = now()
        with self.lock:
            self.db.execute("insert into users (account, label, created, last_seen) values (?, ?, ?, ?) "
                            "on conflict(account) do update set label = excluded.label, last_seen = excluded.last_seen",
                            (account[:100], label[:100], t, t))
            self.db.commit()

    def user(self, account: str) -> dict | None:
        row = self.db.execute("select account, label, created, last_seen from users where account = ?",
                              (account,)).fetchone()
        return dict(zip(("account", "label", "created", "last_seen"), row)) if row else None

    def runs_today(self, account: str, day: str | None = None) -> int:
        row = self.db.execute("select runs from daily where day = ? and account = ?",
                              (day or today(), account)).fetchone()
        return row[0] if row else 0

    def active_runs(self, account: str | None = None) -> int:
        sql, args = "select count(*) from runs where status in (?, ?)", list(ACTIVE)
        if account is not None:
            sql += " and account = ?"
            args.append(account)
        return self.db.execute(sql, args).fetchone()[0]

    def run_ids(self, account: str) -> list[str]:
        return [r[0] for r in self.db.execute("select id from runs where account = ?", (account,))]

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

    def stats(self) -> dict:
        """Aggregates for the owner. No links, no labels."""
        q = self.db.execute
        by_status = {s: n for s, n in q("select status, count(*) from runs group by status")}
        g = q("select runs from global_daily where day = ?", (today(),)).fetchone()
        return {"users": q("select count(*) from users").fetchone()[0],
                "runs": sum(by_status.values()), "runs_by_status": by_status,
                "runs_today": g[0] if g else 0, "shared": q("select count(*) from runs where share_slug is not null").fetchone()[0]}
