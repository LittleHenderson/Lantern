"""SQLite store for cloud mode: accounts (provider id + label), runs, per-day counters, and what is still to be
removed from the disk (`leftovers`: a kind and a name, written in the same step as the delete that owes it).

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
  label text, created text, last_seen text,
  ai_consent text);                  -- when the person agreed to send code to the model (null: not yet)
create table if not exists runs (
  id text primary key,               -- random, unguessable
  account text not null,
  link text not null, host text, privacy text not null,
  status text not null,              -- queued | running | done | error | blocked
  stage text, error text,
  created text not null, started text, finished text,
  commit_sha text, summary text,     -- summary: JSON counts + score, written by the worker
  log_tail text,                     -- the last lines of the run's log (no tokens, no file contents)
  share_slug text unique,            -- null until the person clicks Share (off by default)
  explain_status text,               -- null | queued | running | done | error (plain-words explanations)
  explain_error text, explain_summary text);   -- summary: JSON {functions, validated, failed, stopped}
create index if not exists runs_by_account on runs (account, created);
create table if not exists daily (
  day text, account text, runs integer default 0, primary key (day, account));
create table if not exists global_daily (day text primary key, runs integer default 0);
create table if not exists leftovers (
  kind text not null,                -- results | work | upload: which of the service's three folders
  name text not null,                -- one name inside that folder (a run id, a run's work folder, an upload); never a path
  noted text not null,               -- when it was first written down as still to be removed
  tried integer default 0, last_tried text,
  why text,                          -- the reason the last try gave, in Lantern's own words (no file names)
  primary key (kind, name));
"""

ACTIVE = ("queued", "running")
FINISHED = ("done", "error", "blocked")
RUN_FIELDS = ("id", "account", "link", "host", "privacy", "status", "stage", "error", "created", "started", "finished",
              "commit_sha", "summary", "log_tail", "share_slug", "explain_status", "explain_error", "explain_summary")


class LimitReached(Exception):
    """Over a limit; the message is the sentence the person sees."""


def now() -> str:
    return dt.datetime.now(dt.UTC).isoformat()


def until_midnight_utc(now: dt.datetime | None = None) -> str:
    """"in 5 h 20 min (00:00 UTC)": limits reset at midnight UTC, which is not midnight where most people are."""
    now = now or dt.datetime.now(dt.UTC)
    nxt = (now + dt.timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    mins = max(1, int((nxt - now).total_seconds() // 60))
    h, m = divmod(mins, 60)
    return f"in {f'{h} h {m} min' if h else f'{m} min'} (00:00 UTC)"


def today() -> str:
    return dt.datetime.now(dt.UTC).date().isoformat()


class Store:
    def __init__(self, path: str):
        self.lock = threading.RLock()   # one connection shared by the web server and the worker threads
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("pragma journal_mode=wal")
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("pragma table_info(runs)")}
        for col in ("log_tail", "explain_status", "explain_error", "explain_summary"):   # an earlier database
            if col not in cols:
                self.db.execute(f"alter table runs add column {col} text")
        if "ai_consent" not in {r[1] for r in self.db.execute("pragma table_info(users)")}:
            self.db.execute("alter table users add column ai_consent text")
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

    def consent(self, account: str) -> str | None:
        row = self._one("select ai_consent from users where account = ?", (account,))
        return row[0] if row else None

    def set_consent(self, account: str, on: bool) -> None:
        with self.lock:
            self.db.execute("update users set ai_consent = ? where account = ?", (now() if on else None, account))
            self.db.commit()

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

    def all_run_ids(self) -> set[str]:
        return {r[0] for r in self._all("select id from runs")}

    def delete_user(self, account: str) -> list[str]:
        """Forget an account: its user row, runs and counters. Returns the run ids so the caller removes their
        result folders; each is written down as still to be removed in this same step (see `delete_run`)."""
        with self.lock:
            ids = self.run_ids(account)
            for rid in ids:
                self._owe("results", rid)
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
                raise LimitReached(f"You've used today's {per_day} runs. More are available {until_midnight_utc()}.")
            allr = q("select runs from global_daily where day = ?", (day,)).fetchone()
            if (allr[0] if allr else 0) >= global_per_day:
                raise LimitReached(f"Lantern has reached today's limit of runs for everyone. Try again {until_midnight_utc()}.")
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
        for k in ("summary", "explain_summary"):
            if isinstance(fields.get(k), dict):
                fields[k] = json.dumps(fields[k])
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

    def claim_explain(self, rid: str) -> bool:
        """Explanations queued -> running, for exactly one worker thread."""
        with self.lock:
            n = self.db.execute("update runs set explain_status = 'running' where id = ? and explain_status = 'queued'",
                                (rid,)).rowcount
            self.db.commit()
        return n == 1

    def queue_explain(self, rid: str) -> bool:
        """Mark a finished run's explanations queued, unless they are already queued or running."""
        with self.lock:
            n = self.db.execute("update runs set explain_status = 'queued', explain_error = null where id = ? and "
                                "status = 'done' and coalesce(explain_status, '') not in ('queued', 'running')",
                                (rid,)).rowcount
            self.db.commit()
        return n == 1

    def busy(self, account: str | None = None) -> int:
        """Runs going, plus explanations being written: what must finish before deleting."""
        sql = "select count(*) from runs where (status in (?, ?) or explain_status in (?, ?))"
        args = [*ACTIVE, *ACTIVE]
        if account is not None:
            sql += " and account = ?"
            args.append(account)
        return self._one(sql, args)[0]

    def run(self, rid: str) -> dict | None:
        row = self._one(f"select {', '.join(RUN_FIELDS)} from runs where id = ?", (rid,))   # nosec B608 - our own column names
        return self._run_dict(row) if row else None

    def runs(self, account: str, limit: int = 100) -> list[dict]:
        rows = self._all(f"select {', '.join(RUN_FIELDS)} from runs where account = ? "   # nosec B608 - our own column names
                         "order by created desc limit ?", (account, limit))
        return [self._run_dict(r) for r in rows]

    def unfinished(self) -> list[dict]:
        rows = self._all(f"select {', '.join(RUN_FIELDS)} from runs where status in (?, ?) "   # nosec B608 - our own column names
                         "order by created", ACTIVE)
        return [self._run_dict(r) for r in rows]

    # ---- share, delete, retention ----
    def set_share(self, rid: str, on: bool) -> str | None:
        """Turn the run's public link on (keeping the slug it already has) or off. Returns the slug, or None."""
        with self.lock:
            if not on:
                self.db.execute("update runs set share_slug = null where id = ?", (rid,))
                self.db.commit()
                return None
            row = self.db.execute("select share_slug from runs where id = ?", (rid,)).fetchone()
            if row and row[0]:
                return row[0]
            slug = secrets.token_urlsafe(18)     # 144 random bits: unguessable, and unrelated to the run id
            self.db.execute("update runs set share_slug = ? where id = ?", (slug, rid))
            self.db.commit()
            return slug

    def run_by_slug(self, slug: str) -> dict | None:
        if not isinstance(slug, str) or not 16 <= len(slug) <= 40:
            return None
        row = self._one(f"select {', '.join(RUN_FIELDS)} from runs where share_slug = ?", (slug,))   # nosec B608 - our own column names
        return self._run_dict(row) if row else None

    def delete_run(self, rid: str) -> None:
        """Forget a run. In the same step its result files are written down as still to be removed, so a service
        that is cut off between the two, or whose disk refuses, finishes the delete later (`cleanup.Cleanup`)."""
        with self.lock:
            self.db.execute("delete from runs where id = ?", (rid,))
            self._owe("results", rid)
            self.db.commit()

    # ---- what is still to be removed from the disk ----
    def _owe(self, kind: str, name: str) -> None:
        self.db.execute("insert into leftovers (kind, name, noted) values (?, ?, ?) on conflict(kind, name) do nothing",
                        (kind, name, now()))

    def note_leftover(self, kind: str, name: str) -> None:
        """Write down that `name` in the folder for `kind` is still to be removed. The first time stands."""
        with self.lock:
            self._owe(kind, name)
            self.db.commit()

    def leftover_failed(self, kind: str, name: str, why: str) -> None:
        with self.lock:
            self.db.execute("update leftovers set tried = tried + 1, last_tried = ?, why = ? where kind = ? and name = ?",
                            (now(), str(why)[:300], kind, name))
            self.db.commit()

    def forget_leftover(self, kind: str, name: str) -> None:
        with self.lock:
            self.db.execute("delete from leftovers where kind = ? and name = ?", (kind, name))
            self.db.commit()

    def leftovers(self) -> list[dict]:
        rows = self._all("select kind, name, noted, tried, last_tried, why from leftovers order by noted, kind, name")
        return [dict(zip(("kind", "name", "noted", "tried", "last_tried", "why"), r)) for r in rows]

    def oldest_leftover(self) -> str | None:
        return self._one("select min(noted) from leftovers")[0]

    def oldest_finished(self) -> str | None:
        """When the longest-finished run that is still listed ended (for "is the retention pass behind")."""
        return self._one("select min(coalesce(finished, created)) from runs where status in (?, ?, ?)", FINISHED)[0]

    def expired(self, days: int) -> list[str]:
        """Finished runs older than `days` (0 = none: results are kept until the person deletes them)."""
        if days <= 0:
            return []
        cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(days=days)).isoformat()
        return [r[0] for r in self._all("select id from runs where status in (?, ?, ?) and coalesce(finished, created) < ?",
                                        (*FINISHED, cutoff))]

    @staticmethod
    def _run_dict(row) -> dict:
        d = dict(zip(RUN_FIELDS, row))
        for k in ("summary", "explain_summary"):
            try:
                d[k] = json.loads(d[k]) if d[k] else None
            except ValueError:
                d[k] = None
        return d

    def stats(self) -> dict:
        """Aggregates for the owner. No links, no labels."""
        by_status = {s: n for s, n in self._all("select status, count(*) from runs group by status")}
        g = self._one("select runs from global_daily where day = ?", (today(),))
        return {"users": self._one("select count(*) from users")[0],
                "runs": sum(by_status.values()), "runs_by_status": by_status, "runs_today": g[0] if g else 0,
                "shared": self._one("select count(*) from runs where share_slug is not null")[0]}
