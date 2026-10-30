"""Open a repository from a link: `lantern analyze https://github.com/you/app`, or a link pasted into the app.

The repository is cloned shallowly into LANTERN_HOME/repos/<host>/<owner>/<name> (default ~/.lantern/repos) and then
treated exactly like a local folder: the clone is as untrusted as any other analyzed repo. Only https links to the
public forges in KNOWN_HOSTS (plus hosts named in LANTERN_GIT_HOSTS) are accepted, so a link pasted from a chat cannot
point this machine at a loopback or private address; a `git@host:owner/name` address is turned into https; a link
with a user name or token in it is refused; git runs with prompts off, so a private repository fails fast with a
message instead of hanging a job; and the files are measured before checkout and refused above LANTERN_CLONE_MAX_MB.
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

HTTPS = re.compile(r"^https://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?"
                   r"/(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?"
                   r"(?:/(?:tree|src|-/tree|commits?)/(?P<branch>[^\s?#/]+)[^\s?#]*)?(?:[?#]\S*)?$")
SSH = re.compile(r"^(?:ssh://)?git@(?P<host>[A-Za-z0-9.-]+):(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?$")
KNOWN_HOSTS = frozenset({"github.com", "www.github.com", "gitlab.com", "www.gitlab.com", "bitbucket.org",
                         "codeberg.org", "gitea.com", "git.sr.ht", "dev.azure.com", "huggingface.co", "gitee.com"})
DEFAULT_MAX_MB = 500


def allowed_hosts() -> frozenset[str]:
    """The public forges, plus your own servers from LANTERN_GIT_HOSTS (comma-separated host names)."""
    extra = {h.strip().lower() for h in os.environ.get("LANTERN_GIT_HOSTS", "").split(",") if h.strip()}
    return KNOWN_HOSTS | frozenset(extra)


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
    host, owner, name, branch = m.group("host").lower(), m.group("owner"), m.group("name"), m.group("branch")
    if host not in allowed_hosts():
        raise ValueError("Lantern clones from github.com, gitlab.com, bitbucket.org, codeberg.org and a few other "
                         "public forges. For your own git server, set LANTERN_GIT_HOSTS to its host name; "
                         "otherwise clone the repository yourself and add the folder.")
    for part in (owner, name):
        if part in (".", "..") or part.startswith(".") or ".." in part:
            raise ValueError("not a repository link")
    if branch and (".." in branch or branch.startswith("-")):
        raise ValueError("not a repository link")
    return {"host": host, "owner": owner, "name": name, "branch": branch, "url": f"https://{host}/{owner}/{name}"}


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


def max_mb() -> int:
    """Size cap for a clone's files, in MB (LANTERN_CLONE_MAX_MB; 0 means no cap)."""
    try:
        return int(os.environ.get("LANTERN_CLONE_MAX_MB", DEFAULT_MAX_MB))
    except ValueError:
        return DEFAULT_MAX_MB


def tree_mb(dest: Path) -> float:
    """Size of the files at HEAD, from the index, before anything is written to the working tree."""
    r = _git(["ls-tree", "-r", "-l", "HEAD"], cwd=dest, timeout=120)
    total = 0
    for line in r.stdout.splitlines():
        parts = line.split(None, 4)   # mode type sha size path
        if len(parts) >= 4 and parts[3].isdigit():
            total += int(parts[3])
    return total / 1_000_000


def fetch(url: str, dest: Path, branch: str | None = None, timeout: int = 900) -> None:
    """`git clone --depth 1` of `url` into `dest` (an empty or missing folder), without a checkout first: the files
    are measured from the index and refused above the size cap, then checked out. RuntimeError with a plain message."""
    args = (["clone", "--depth", "1", "--single-branch", "--no-checkout"] + (["--branch", branch] if branch else [])
            + ["--", url, str(dest)])
    r = _git(args, cwd=None, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError("could not clone it: " + _tail(r.stderr) +
                           ". If the repository is private, clone it yourself and add the folder.")
    cap = max_mb()
    size = tree_mb(dest)
    if cap and size > cap:
        _rmtree(dest)
        raise RuntimeError(f"the repository's files add up to {size:,.0f} MB, above Lantern's {cap} MB limit "
                           "(LANTERN_CLONE_MAX_MB). Clone it yourself and add the folder.")
    r = _git(["reset", "--hard", "--quiet"], cwd=dest, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError("could not check out the files: " + _tail(r.stderr))


def _rmtree(path: Path) -> None:
    """Remove a clone. Git marks its object files read-only, which on Windows makes a plain rmtree fail halfway and
    leave the folder behind; clearing the bit (on the file and its folder) and retrying is the standard recipe."""
    def unlock(func, p, _exc):
        for q in (p, os.path.dirname(p)):
            try:
                os.chmod(q, stat.S_IRWXU)
            except OSError:
                pass
        func(p)
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=unlock)
    else:
        shutil.rmtree(path, onerror=unlock)


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
