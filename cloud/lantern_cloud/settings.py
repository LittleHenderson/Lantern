"""Everything the cloud service can be told through its environment. Same style as the gateway's `Settings`.

Owner decisions (2026-11-03) baked into the defaults:
  * clones from every public forge Lantern knows (`lantern.remote.KNOWN_HOSTS`), not GitHub only;
  * results are kept until the person deletes them (`LANTERN_CLOUD_RETENTION_DAYS=0`);
  * cloud runs may spend the person's free allowance on explanations (v1.5, through the gateway);
  * share links are off until the person clicks Share on a run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    # Sign-in is the gateway's: the website gets a gateway token (GitHub/Google), and this service asks the gateway
    # whose it is (`GET <gateway>/whoami`). One account, one token, for the allowance and for cloud runs.
    gateway_url: str = field(default_factory=lambda: os.environ.get(
        "LANTERN_GATEWAY_URL", "https://lantern-gateway.fly.dev/v1").rstrip("/"))
    # How long a "this token is account X" answer is reused before asking the gateway again (seconds).
    identity_ttl: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_IDENTITY_TTL", 300))
    admin_secret: str = field(default_factory=lambda: os.environ.get("LANTERN_ADMIN_SECRET", ""))
    public_url: str = field(default_factory=lambda: os.environ.get(
        "LANTERN_PUBLIC_URL", "https://lantern-cloud.fly.dev").rstrip("/"))
    db_path: str = field(default_factory=lambda: os.environ.get("LANTERN_CLOUD_DB", "lantern_cloud.db"))
    # Where each run's result files go (one folder per run). A Fly volume in production.
    results_dir: str = field(default_factory=lambda: os.environ.get("LANTERN_CLOUD_RESULTS", "cloud-results"))
    # Limits. Over a limit, the person gets HTTP 429 and a sentence that says which one and when it resets.
    runs_per_day: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_RUNS_PER_DAY", 10))
    global_runs_per_day: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_GLOBAL_RUNS_PER_DAY", 300))
    concurrent_jobs: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_CONCURRENT_JOBS", 2))
    # The same variable `lantern.remote` reads for its size check (set in cloud/Dockerfile and cloud/fly.toml).
    clone_max_mb: int = field(default_factory=lambda: _env_int("LANTERN_CLONE_MAX_MB", 200))
    job_timeout: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_JOB_SECONDS", 600))
    # Minutes with no request and no run before the service stops itself (Fly then keeps the machine stopped, and
    # bills nothing for it, until the next visitor). 0 = never.
    idle_minutes: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_IDLE_MINUTES", 0))
    # Temp folders for runs in progress (clone + analysis output); emptied at start-up and after every run.
    work_dir: str = field(default_factory=lambda: os.environ.get("LANTERN_CLOUD_WORK", "cloud-work"))
    # Dependency audits (pip-audit, npm audit on lock files) need the network; off only in tests.
    audits: bool = field(default_factory=lambda: os.environ.get("LANTERN_CLOUD_AUDITS", "1") not in ("0", "false", "no"))
    # Runs one person may have queued or running at once.
    per_user_active: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_ACTIVE_PER_USER", 1))
    # 0 = keep results until the person deletes them (the owner's choice). A positive number deletes runs that old.
    retention_days: int = field(default_factory=lambda: _env_int("LANTERN_CLOUD_RETENTION_DAYS", 0))
    # Comma-separated hosts allowed for clones. Empty = every host `lantern.remote` accepts.
    allowed_hosts: str = field(default_factory=lambda: os.environ.get("LANTERN_CLOUD_HOSTS", ""))
    default_privacy: str = "structure"

    def limits(self) -> dict:
        """The limits a person may see (health, /v1/me). No secrets, no counters of other people."""
        return {"runs_per_day": self.runs_per_day, "concurrent_jobs": self.concurrent_jobs,
                "clone_max_mb": self.clone_max_mb, "job_seconds": self.job_timeout,
                "retention_days": self.retention_days or None, "default_privacy": self.default_privacy}

    def hosts(self) -> list[str] | None:
        """Allowed clone hosts, or None for every host `lantern.remote` accepts."""
        hs = [h.strip().lower() for h in self.allowed_hosts.split(",") if h.strip()]
        return hs or None
