"""Open a repository from a link: `lantern analyze https://github.com/you/app`, or a link pasted into the app.

The repository is cloned shallowly into LANTERN_HOME/repos/<host>/<owner>/<name> (default ~/.lantern/repos) and then
treated exactly like a local folder: the clone is as untrusted as any other analyzed repo. Only https links are
accepted (a `git@host:owner/name` address is turned into one), never a link with a user name or token in it, and git
runs with prompts off, so a private repository fails fast with a message instead of hanging a job.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

HTTPS = re.compile(r"^https://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::\d{1,5})?"
                   r"/(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?"
                   r"(?:/(?:tree|src|-/tree|commits?)/(?P<branch>[^\s?#/]+)[^\s?#]*)?(?:[?#]\S*)?$")
SSH = re.compile(r"^(?:ssh://)?git@(?P<host>[A-Za-z0-9.-]+):(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?$")


def looks_like_url(s: str) -> bool:
    """Something the user typed that is a link rather than a folder (so a bad link gets a link error)."""
    s = s.strip().lower()
    return s.startswith(("https://", "http://", "git@", "ssh://", "git://")) or bool(re.match(r"^[a-z]+\.[a-z]+/", s))


def parse(link: str) -> dict:
    """host, owner, name, branch (or None) and the https url to clone. ValueError says what is wrong in plain words."""
    s = link.strip()
    if s.startswith(("http://", "git://")):
        raise ValueError("use an https:// link")
    m = SSH.match(s)
    if m:
        s = f"https://{m.group('host')}/{m.group('owner')}/{m.group('name')}"
    if re.match(r"^https://[^/]*@", s):
        raise ValueError("remove the user name or token from the link; Lantern clones public repositories "
                         "(for a private one, clone it yourself and add the folder)")
    m = HTTPS.match(s)
    if not m:
        raise ValueError("not a repository link; expected https://github.com/<owner>/<repository>")
    host, owner, name, branch = m.group("host"), m.group("owner"), m.group("name"), m.group("branch")
    for part in (owner, name):
        if part in (".", "..") or part.startswith(".") or ".." in part:
            raise ValueError("not a repository link")
    if branch and (".." in branch or branch.startswith("-")):
        raise ValueError("not a repository link")
    return {"host": host.lower(), "owner": owner, "name": name, "branch": branch,
            "url": f"https://{host.lower()}/{owner}/{name}"}


def repos_dir() -> Path:
    return Path(os.environ.get("LANTERN_HOME") or Path.home() / ".lantern") / "repos"


def destination(info: dict, root: Path | None = None) -> Path:
    return (root or repos_dir()) / info["host"] / info["owner"] / info["name"]


def clone(link: str, log=None, dest: Path | None = None, root: Path | None = None) -> Path:
    """Clone the repository the link names (shallow), or fast-forward an earlier clone, and return its folder."""
    info = parse(link)
    dest = dest or destination(info, root)
    log = log or (lambda m: None)
    if (dest / ".git").exists():
        log(f"updating {dest}")
        r = _git(["pull", "--ff-only", "--quiet"], cwd=dest)
        if r.returncode != 0:
            log("could not update it, kept the copy that was there: " + _tail(r.stderr))
        return dest
    if dest.exists() and any(dest.iterdir()):
        raise RuntimeError(f"{dest} already exists and is not a git clone. Add it as a folder, or remove it.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"cloning {info['url']}" + (f" (branch {info['branch']})" if info["branch"] else "") + f" into {dest}")
    fetch(info["url"], dest, info["branch"])
    return dest


def fetch(url: str, dest: Path, branch: str | None = None, timeout: int = 900) -> None:
    """`git clone --depth 1` of `url` into `dest` (an empty or missing folder). RuntimeError with a plain message."""
    args = ["clone", "--depth", "1", "--single-branch"] + (["--branch", branch] if branch else []) + ["--", url, str(dest)]
    r = _git(args, cwd=None, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError("could not clone it: " + _tail(r.stderr) +
                           ". If the repository is private, clone it yourself and add the folder.")


def _git(args: list[str], cwd: Path | None, timeout: int = 900) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
    try:
        return subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("git is not installed. Install Git, or clone the repository yourself and add the folder.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git took longer than {timeout} seconds; try again, or clone it yourself and add the folder.") from None


def _tail(stderr: str) -> str:
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    msg = lines[-1] if lines else "git gave no reason"
    return re.sub(r"https://[^/\s]*@", "https://", msg)[:200]   # never echo credentials from a URL
