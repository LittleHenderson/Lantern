"""Open a repository from a link: `lantern analyze https://github.com/you/app`, or a link pasted into the app.

The repository is cloned shallowly into LANTERN_HOME/repos/<host>/<owner>/<name> (default ~/.lantern/repos) and then
treated exactly like a local folder: the clone is as untrusted as any other analyzed repo. Only https links to the
public forges in KNOWN_HOSTS (plus hosts named in LANTERN_GIT_HOSTS) are accepted, so a link pasted from a chat cannot
point this machine at a loopback or private address; a `git@host:owner/name` address is turned into https; a link
with a user name or token in it is refused; git runs with prompts off, so a private repository fails fast with a
message instead of hanging a job; and the files are measured before checkout and refused above LANTERN_CLONE_MAX_MB.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path

from . import programs, removal, results

HTTPS = re.compile(r"^https://(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::(?P<port>\d{1,5}))?"
                   r"/(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?"
                   r"(?:/(?:tree|src|-/tree|commits?)/(?P<branch>[^\s?#/]+)[^\s?#]*)?(?:[?#]\S*)?$")
SSH = re.compile(r"^(?:ssh://)?git@(?P<host>[A-Za-z0-9.-]+):(?P<owner>[\w.-]+)/(?P<name>[\w.-]+?)(?:\.git)?/?$")
KNOWN_HOSTS = frozenset({"github.com", "www.github.com", "gitlab.com", "www.gitlab.com", "bitbucket.org",
                         "codeberg.org", "gitea.com", "git.sr.ht", "dev.azure.com", "huggingface.co", "gitee.com"})
DEFAULT_MAX_MB = 500


def allowed_hosts() -> frozenset[str]:
    """The public forges, plus your own servers from LANTERN_GIT_HOSTS (comma-separated host names; `host` allows any
    port on it, `host:port` only that port)."""
    return KNOWN_HOSTS | _own_hosts()


def _own_hosts() -> frozenset[str]:
    return frozenset(h.strip().lower() for h in os.environ.get("LANTERN_GIT_HOSTS", "").split(",") if h.strip())


def _host_allowed(host: str, port: str | None) -> bool:
    """A public forge on the standard port; your own server on any port (`host`) or on the one named (`host:port`)."""
    if port is None:
        return host in allowed_hosts()
    own = _own_hosts()
    return host in own or f"{host}:{port}" in own


def _port_refusal(host: str, port: str | None) -> str | None:
    """Why a known host was refused because of its port, in one sentence (None when the host itself is unknown)."""
    used = f"port {port}" if port else "the standard port 443"
    ports = sorted(e.split(":", 1)[1] for e in _own_hosts() if e.startswith(host + ":"))
    if ports:
        return (f"LANTERN_GIT_HOSTS allows {host} only on port {', '.join(ports)}, and this link uses {used}. "
                f"Add {host} without a port to allow any port on it.")
    if port and host in KNOWN_HOSTS:
        return f"{host} is cloned only on the standard port 443; this link uses port {port}."
    return None


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
    port = m.group("port")
    if port is not None and not 0 < int(port) < 65536:
        raise ValueError("not a repository link: the port must be between 1 and 65535")
    port = None if port in (None, "443") else str(int(port))
    if not _host_allowed(host, port):
        why = _port_refusal(host, port)
        if why:
            raise ValueError(why)
        raise ValueError("Lantern clones from github.com, gitlab.com, bitbucket.org, codeberg.org and a few other "
                         "public forges. For your own git server, set LANTERN_GIT_HOSTS to its host name; "
                         "otherwise clone the repository yourself and add the folder.")
    for part in (owner, name):
        if part in (".", "..") or part.startswith(".") or ".." in part:
            raise ValueError("not a repository link")
    if branch and (".." in branch or branch.startswith("-")):
        raise ValueError("not a repository link")
    netloc = f"{host}:{port}" if port else host   # kept: a self-hosted forge on 8443 is cloned from 8443, not 443
    return {"host": host, "port": port, "owner": owner, "name": name, "branch": branch,
            "url": f"https://{netloc}/{owner}/{name}"}


def repos_dir() -> Path:
    return Path(os.environ.get("LANTERN_HOME") or Path.home() / ".lantern") / "repos"


def destination(info: dict, root: Path | None = None) -> Path:
    """LANTERN_HOME/repos/<host>/<owner>/<name>; a non-default port is part of the folder (`git.example_8443`, no
    colon, which Windows does not allow), so two forges on one host never share a checkout."""
    host = f"{info['host']}_{info['port']}" if info.get("port") else info["host"]
    return (root or repos_dir()) / host / info["owner"] / info["name"]


def clone(link: str, log=None, dest: Path | None = None, root: Path | None = None) -> Path:
    """Clone the repository the link names (shallow), or fast-forward an earlier clone, and return its folder."""
    info = parse(link)
    dest = dest or destination(info, root)
    log = log or (lambda m: None)
    if (dest / ".git").exists():
        log(f"updating {dest}")
        _git(["config", "core.symlinks", "false"], cwd=dest)   # a clone an earlier Lantern made: no new link from here on
        r = _git(["pull", "--ff-only", "--quiet"], cwd=dest)
        if r.returncode != 0:
            log("could not update it, kept the copy that was there: " + _tail(r.stderr))
        if not has_files(dest):   # an earlier checkout failed and left only .git: finish it, under the same cap
            log("the earlier clone has no files yet; checking them out")
            _checkout(dest)
        else:
            missing = missing_files(dest)
            if missing:   # an earlier checkout stopped part-way: write the missing files, touch nothing else
                log(f"{len(missing)} file(s) were missing from the earlier checkout; restoring them")
                _git(["checkout-index", "-a"], cwd=dest)   # writes only files that do not exist yet (exit 1 otherwise)
            check_complete(dest, "could not restore")
        _mark(dest)
        return dest
    if dest.exists() and any(dest.iterdir()):
        raise RuntimeError(f"{dest} already exists and is not a git clone. Add it as a folder, or remove it.")
    dest.parent.mkdir(parents=True, exist_ok=True)
    log(f"cloning {info['url']}" + (f" (branch {info['branch']})" if info["branch"] else "") + f" into {dest}")
    fetch(info["url"], dest, info["branch"])
    left = skipped(dest)
    if left:
        log(f"left out {left['files']} file(s) Lantern does not read (pictures, videos, archives, model files; "
            f"{left['mb']:,.1f} MB) to stay under the {left['cap_mb']} MB limit; the code is {left['kept_mb']:,.1f} MB")
    return dest


def max_mb() -> int:
    """Size cap for a clone's files, in MB (LANTERN_CLONE_MAX_MB; 0 means no cap)."""
    try:
        return int(os.environ.get("LANTERN_CLONE_MAX_MB", DEFAULT_MAX_MB))
    except ValueError:
        return DEFAULT_MAX_MB


def tree_files(dest: Path) -> list[tuple[str, int]]:
    """(path, bytes) of every file at HEAD, read from git before anything is written to the working tree."""
    r = _git(["ls-tree", "-r", "-l", "-z", "HEAD"], cwd=dest, timeout=120)
    out = []
    for entry in r.stdout.split("\0"):
        meta, _, path = entry.partition("\t")
        parts = meta.split()   # mode type sha size
        if path and len(parts) == 4 and parts[3].isdigit():
            out.append((path, int(parts[3])))
    return out


def tree_mb(dest: Path) -> float:
    """Size of the files at HEAD, from the index, before anything is written to the working tree."""
    return sum(n for _, n in tree_files(dest)) / 1_000_000


# Files Lantern never reads: pictures, sound, video, fonts, archives, compiled programs, model weights, datasets and
# design files. A repository over the size cap is checked without them when that brings it under the cap; nothing
# Lantern reads (source, config, manifests, lock files, notebooks, text) is ever left out.
BULK_EXT = frozenset("""
png jpg jpeg gif webp bmp ico icns tif tiff heic heif avif psd xcf raw cr2 nef svgz
mp4 mov avi mkv webm m4v wmv flv mpg mpeg 3gp mp3 wav flac ogg oga m4a aac wma aiff opus mid midi
ttf otf woff woff2 eot
zip tar gz tgz bz2 xz 7z rar zst lz4 jar war aar apk aab ipa dmg iso pkg deb rpm msi cab
exe dll so dylib a o obj lib class pyc pyo wasm node bin dat
pt pth ckpt safetensors onnx h5 hdf5 pb tflite gguf ggml mlmodel caffemodel joblib keras
npy npz parquet feather arrow orc avro pkl pickle mat sav rds rdata
db sqlite sqlite3 mdb accdb
pdf ai eps sketch fig xd blend fbx glb gltf stl 3ds max dae usdz unitypackage
""".split())
BULK_FILE_MB = 20      # any other single file larger than this is data, unless it has a type Lantern reads
READ_EXT = frozenset("""
py pyi js jsx ts tsx mjs cjs go rs java kt kts swift dart cs cshtml razor php rb rake erb c h cc cpp cxx hpp hh m mm
html htm vue svelte astro json jsonc yaml yml toml xml plist gradle properties cfg ini conf env ipynb sql sh bash ps1
tf lock txt md
""".split())
SKIPPED = "lantern-skipped.json"   # in .git: the files a clone left out, for the report's Limits


def is_bulk(path: str, size: int) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    ext = name.rsplit(".", 1)[1] if "." in name else ""
    return ext in BULK_EXT or (size > BULK_FILE_MB * 1_000_000 and ext not in READ_EXT and not name.startswith("."))


def _pattern(path: str) -> str:
    """A sparse-checkout line that matches exactly this one path (wildcards and a trailing space escaped)."""
    p = re.sub(r"([\\*?\[])", r"\\\1", path)
    return "!/" + (p[:-1] + "\\ " if p.endswith(" ") else p)


def skipped(folder: Path) -> dict | None:
    """What a Lantern clone left out to stay under the size cap: {files, mb, examples}, or None."""
    try:   # Lantern's own note, kept in a folder that may have come from anywhere: read only as a plain file
        d = json.loads(results.plain(Path(folder) / ".git" / SKIPPED)[0] or "null")
    except (ValueError, RecursionError):
        return None
    return d if isinstance(d, dict) and isinstance(d.get("files"), int) else None


# A repository can hold links to any path of the computer it is cloned on. Lantern's clones are written without
# them (2026-11-10): git then writes a link as a small file that holds the link's own text, as it does on a Windows
# without links, and keeps the setting in the clone, so a later update writes none either. The readers refuse a link
# that leads out of a project themselves (`python_frontend.inside_repo`); this is for every program that reads a
# clone after them.
NO_LINKS = ["-c", "core.symlinks=false"]


def fetch(url: str, dest: Path, branch: str | None = None, timeout: int = 900, auth: str | None = None) -> None:
    """`git clone --depth 1` of `url` into `dest` (an empty or missing folder), without a checkout first: the files
    are measured from the index and refused above the size cap, then checked out. RuntimeError with a plain message.
    The 900 s limit is for a slow transfer; a server that never answers the connection is given up on by git itself
    after about 300 s (libcurl's connect timeout), so that message ("Connection timed out after 300015 milliseconds")
    comes first.
    `auth`: a read-only GitHub token (Lantern cloud's "Connect GitHub"), handed to git as an HTTP header through
    environment variables only (never in the link, `.git/config` or the log)."""
    dest = Path(dest)
    # Whatever fails below, what the copy left is removed, so the folder must hold nothing of anyone's when it
    # begins. Until 2026-11-10 this was only written above, not checked: a copy into a folder that held files was
    # refused by git, and the folder was then deleted with everything in it.
    if os.path.lexists(dest) and (dest.is_symlink() or not dest.is_dir() or any(dest.iterdir())):
        raise RuntimeError(f"{dest} already exists and is not empty. Lantern copies a repository only into a new "
                           "or empty folder.")
    args = (["clone", *NO_LINKS, "--depth", "1", "--single-branch", "--no-checkout"]
            + (["--branch", branch] if branch else []) + ["--", url, str(dest)])
    try:
        r = _git(args, cwd=None, timeout=timeout, **({"env": _auth_env(url, auth)} if auth else {}))
    except RuntimeError as e:
        left = _left_behind(dest)   # a clone stopped by the timeout can leave a partial folder behind
        if left:
            raise RuntimeError(str(e) + left) from None
        raise
    if r.returncode != 0:
        raise RuntimeError("could not clone it: " + _tail(r.stderr) +
                           ". If the repository is private, clone it yourself and add the folder." + _left_behind(dest))
    _mark(dest)
    _checkout(dest, timeout, made=True)


def has_files(dest: Path) -> bool:
    """Whether a clone has working files, not just `.git`."""
    return dest.is_dir() and any(p.name != ".git" for p in dest.iterdir())


def missing_files(dest: Path) -> list[str] | None:
    """Files in the clone's index that are not in its working tree: what a checkout that stopped part-way left out
    (edited files are not missing, and are never touched). None when git cannot list them, which callers treat as
    "not known to be complete" rather than "nothing missing".
    Asked through `gitfacts.deleted`, which does not obey the folder's own git settings: `pipeline.analyze` asks
    this of any folder that carries the clone mark, and anyone can put that mark, and a command for git to run
    (`core.fsmonitor`), into a folder they hand over."""
    if not programs.find("git"):
        raise RuntimeError("git is not installed. Install Git, or clone the repository yourself and add the folder.")
    from . import gitfacts   # here, not above: gitfacts starts git through this module's `run_bounded`
    return gitfacts.deleted(dest)


MARK = "lantern-clone"   # a file in .git naming a folder Lantern cloned (git leaves unknown files in .git alone)


def _mark(dest: Path) -> None:
    try:
        (dest / ".git" / MARK).write_text("cloned by Lantern\n", encoding="utf-8")
    except OSError:
        pass


def is_clone(folder: Path) -> bool:
    """Whether Lantern cloned this folder: marked at clone time, or kept under LANTERN_HOME/repos (clones made before
    the mark). A folder of your own that happens to be a git repository is not one: a file you deleted there is yours
    to delete, and is analyzed as it is."""
    folder = Path(folder)
    if not (folder / ".git").is_dir():
        return False
    if (folder / ".git" / MARK).exists():
        return True
    try:
        return folder.resolve().is_relative_to(repos_dir().resolve())
    except OSError:
        return False


def check_complete(dest: Path, what: str = "this clone has") -> None:
    """Refuse a clone with files missing from its checkout, or whose files git cannot list: a missing file is a place
    a finding could have been, so analyzing what is there would give a clean-looking report of part of a repository."""
    still = missing_files(dest)
    if still is None:
        raise RuntimeError(f"git could not list the files of {dest}, so they cannot be checked for missing ones. "
                           "Remove it and try again, or clone it yourself and add the folder.")
    if still:
        raise RuntimeError(f"{what} {len(still)} missing file(s), starting with {still[0]}. "
                           f"Remove {dest} and try again, or clone it yourself and add the folder.")


def _checkout(dest: Path, timeout: int = 900, made: bool = False) -> None:
    """Measure the files from the index, refuse above the cap, then check them out. Whatever fails, nothing is left
    behind: a folder holding only `.git` would otherwise pass as a finished clone and analyze as an empty project
    (seen with a reserved Windows file name such as `aux.txt`, a path over MAX_PATH, or a full disk).
    Only a folder Lantern cloned is removed (`made`: by the call that is running; or `is_clone`). A repository
    folder of the person's own that happens to have no files checked out stays as it is, and the error says why
    the files could not be written."""
    cap = max_mb()
    files = tree_files(dest)
    size = sum(n for _, n in files) / 1_000_000
    if cap and size > cap:
        # Over the cap: leave out what Lantern never reads (pictures, video, archives, model files, datasets).
        bulk = [(p, n) for p, n in files if is_bulk(p, n) and "\n" not in p and "\r" not in p]
        code = size - sum(n for _, n in bulk) / 1_000_000
        if code > cap:
            left = _left_behind(dest) if made or is_clone(dest) else ""
            raise RuntimeError(f"the repository's files add up to {size:,.1f} MB, and still {code:,.1f} MB without "
                               f"the pictures, videos, archives and other files Lantern does not read: above Lantern's "
                               f"{cap} MB limit (LANTERN_CLONE_MAX_MB). Clone it yourself and add the folder." + left)
        sparse = dest / ".git" / "info" / "sparse-checkout"
        sparse.parent.mkdir(parents=True, exist_ok=True)
        sparse.write_text("/*\n" + "".join(_pattern(p) + "\n" for p, _ in bulk), encoding="utf-8", newline="\n")
        _git(["config", "core.sparseCheckout", "true"], cwd=dest)
        biggest = sorted(bulk, key=lambda x: -x[1])[:5]
        (dest / ".git" / SKIPPED).write_text(json.dumps({
            "files": len(bulk), "mb": round(size - code, 1), "kept_mb": round(code, 1), "cap_mb": cap,
            "examples": [p for p, _ in biggest]}), encoding="utf-8")
    r = _git(["reset", "--hard", "--quiet"], cwd=dest, timeout=timeout)
    if r.returncode != 0:
        left = _left_behind(dest) if made or is_clone(dest) else ""
        raise RuntimeError("could not check out the files: " + _tail(r.stderr) +
                           ". Clone it yourself and add the folder." + left)


def remove_tree(path: Path) -> str | None:
    """Remove a clone with everything in it. None when nothing is left; otherwise why not, in one sentence
    (`lantern.removal.remove`: read-only files and folders are no obstacle, which matters on Windows, where git's
    object files are read-only; nothing is raised for what the system refused).

    Only what is inside `path` is changed. Until 2026-11-10 a refused delete had the mode of the thing and of the
    folder it is in set to owner-only, by name: for a `path` that was a link, the folder it pointed at and the
    folder it lay in (a folder all users share, in the test), and the link stayed, without a word."""
    return removal.remove(path)


def _left_behind(dest: Path) -> str:
    """Remove what a copy that failed left in `dest`. Empty when nothing is left; otherwise a sentence for the end
    of the error, so that a folder that stayed is never passed over in silence."""
    why = remove_tree(dest)
    return f" What the failed copy left in {dest} could not be removed ({why}); remove that folder yourself." if why else ""


def _auth_env(url: str, token: str) -> dict:
    """`http.<origin>/.extraHeader` for this one git call, set through GIT_CONFIG_* (git 2.31+), scoped to the host."""
    import base64
    origin = "/".join(url.split("/")[:3]) + "/"
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": f"http.{origin}.extraHeader",
            "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}"}


def _git(args: list[str], cwd: Path | None, timeout: int = 900, env: dict | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never", "GIT_ASKPASS": "", "SSH_ASKPASS": "",
           **(env or {})}
    git = programs.find("git")   # the person's own git, by its full path: never one in the current folder or the clone
    if not git:
        raise RuntimeError("git is not installed. Install Git, or clone the repository yourself and add the folder.")
    try:
        return run_bounded([git, *args], cwd=cwd, env=env, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("git is not installed. Install Git, or clone the repository yourself and add the folder.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git took longer than {timeout} seconds; try again, or clone it yourself and add the folder.") from None


# Helper programs that run beside the analysis (`security.Early`) are waited for in threads of their own. A run
# that stops must leave none of them going: `end_for` ends what those threads wait for and has them start nothing
# more, `forget` is for when the threads have ended (the system hands a thread's number out again).
_WAITED: dict[int, list] = {}     # a thread -> the helper programs it is waiting for
_TOLD: set[int] = set()           # the threads that were told to stop
_WAIT_LOCK = threading.Lock()


def end_for(threads) -> None:
    """End every helper program these threads are waiting for, with everything it started, and have the threads
    start no other: `run_bounded` raises OSError in a thread that was told to stop."""
    threads = set(threads)
    with _WAIT_LOCK:
        _TOLD.update(threads)
        going = [p for t in threads for p in _WAITED.get(t, ())]
    for proc in going:
        _kill_tree(proc)


def forget(threads) -> None:
    with _WAIT_LOCK:
        _TOLD.difference_update(set(threads))


def run_bounded(cmd: list[str], cwd: Path | None = None, env: dict | None = None,
                timeout: float = 900) -> subprocess.CompletedProcess:
    """`subprocess.run(capture_output=True, text=True, timeout=...)`, except that the timeout bounds the call. git
    starts helpers (`git-remote-https`) that inherit its output pipes; `subprocess.run` kills only git, and then waits
    for the pipes to close, which a helper stuck on a silent server keeps open for minutes. The command runs in its
    own process group and the whole group is killed (`taskkill /T` on Windows), then the pipes are dropped.
    The environment is `programs.env`: the helper, and what it starts, are not handed the current folder to look
    for programs or Python files in."""
    env = programs.env(env)
    kw: dict = {}
    if sys.platform == "win32":
        kw["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    me = threading.get_ident()
    with _WAIT_LOCK:
        if me in _TOLD:
            raise OSError("the run was stopped; no helper program is started for it any more")
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace", **kw)
    with _WAIT_LOCK:
        _WAITED.setdefault(me, []).append(proc)
        told = me in _TOLD
    try:
        if told:    # told to stop between the look above and the start
            _kill_tree(proc)
        return _waited_for(proc, cmd, timeout)
    finally:
        with _WAIT_LOCK:
            mine = _WAITED.get(me, [])
            if proc in mine:
                mine.remove(proc)
            if not mine:
                _WAITED.pop(me, None)


def _waited_for(proc: subprocess.Popen, cmd: list[str], timeout: float) -> subprocess.CompletedProcess:
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:   # a helper outside the group still holds a pipe: stop waiting for it
            for f in (proc.stdout, proc.stderr):
                try:
                    f.close()
                except OSError:
                    pass
            proc.wait(timeout=5)
        raise subprocess.TimeoutExpired(cmd, timeout) from None
    except BaseException:
        _kill_tree(proc)
        raise
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)


def _kill_tree(proc: subprocess.Popen) -> None:
    if sys.platform == "win32":
        try:
            taskkill = programs.find("taskkill") or os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                                                "System32", "taskkill.exe")
            subprocess.run([taskkill, "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        import signal
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        proc.kill()
    except OSError:
        pass


def _tail(stderr: str) -> str:
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    msg = lines[-1] if lines else "git gave no reason"
    return re.sub(r"https://[^/\s]*@", "https://", msg)[:200]   # never echo credentials from a URL
