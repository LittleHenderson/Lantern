"""Opening a repository from a link: parsing, cloning with git, the CLI, and the app."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from lantern import remote
from lantern.cli import main

from test_server import FIX, call, srv, wait  # noqa: F401  (srv is a fixture)


@pytest.mark.parametrize("link, host, owner, name, branch", [
    ("https://github.com/Owner/Repo", "github.com", "Owner", "Repo", None),
    ("https://github.com/owner/repo.git/", "github.com", "owner", "repo", None),
    ("  https://github.com/owner/repo?tab=readme-ov-file ", "github.com", "owner", "repo", None),
    ("https://github.com/owner/repo/tree/dev/backend/app", "github.com", "owner", "repo", "dev"),
    ("git@github.com:owner/repo.git", "github.com", "owner", "repo", None),
    ("https://gitlab.com/group/project/-/tree/main", "gitlab.com", "group", "project", "main"),
    ("https://Codeberg.org/team/app.git", "codeberg.org", "team", "app", None),
])
def test_repository_links_are_read(link, host, owner, name, branch):
    info = remote.parse(link)
    assert (info["host"], info["owner"], info["name"], info["branch"]) == (host, owner, name, branch)
    assert info["url"] == f"https://{host}/{owner}/{name}"
    assert remote.destination(info, Path("/r")) == Path("/r") / host / owner / name


@pytest.mark.parametrize("link", [
    "http://github.com/o/r", "git://github.com/o/r", "https://user:tok@github.com/o/r", "https://github.com/o",
    "https://github.com/../x/y", "https://github.com/o/..", "https://github.com/.o/r", "file:///etc/passwd",
    "/home/me/app", "https://github.com/o/r;rm -rf x", "https://github.com/o/r/tree/-x", "https://github.com/o/r/tree/..",
])
def test_bad_links_are_refused(link):
    with pytest.raises(ValueError):
        remote.parse(link)


@pytest.mark.parametrize("link", [
    "https://evil.example.com/o/r", "https://127.0.0.1/o/r", "https://10.0.0.8:8443/o/r", "https://localhost/o/r",
    "https://[::1]/o/r", "https://github.com.evil.example/o/r", "https://git.example.org:8443/team/app.git",
])
def test_links_to_other_hosts_are_refused(link, monkeypatch):
    """A link pasted from a chat must not point this machine at a loopback or private address, or at the sender's
    server: only the public forges are cloned, plus servers the user names in LANTERN_GIT_HOSTS."""
    monkeypatch.delenv("LANTERN_GIT_HOSTS", raising=False)
    with pytest.raises(ValueError, match="public forges"):
        remote.parse(link)


def test_your_own_git_server_can_be_added(monkeypatch):
    monkeypatch.setenv("LANTERN_GIT_HOSTS", "git.example.org, Gitea.Internal")
    info = remote.parse("https://git.example.org:8443/team/app.git")
    assert (info["host"], info["owner"], info["name"]) == ("git.example.org", "team", "app")
    assert remote.parse("https://gitea.internal/o/r")["host"] == "gitea.internal"
    with pytest.raises(ValueError):
        remote.parse("https://other.example.org/o/r")


def test_links_and_folders_are_told_apart():
    assert remote.looks_like_url("https://github.com/o/r") and remote.looks_like_url("git@github.com:o/r.git")
    assert remote.looks_like_url("github.com/o/r")   # a link with the scheme left off gets a link error, not "not a folder"
    assert not remote.looks_like_url("/home/me/app") and not remote.looks_like_url("C:\\Users\\me\\app")
    assert not remote.looks_like_url("my-app") and not remote.looks_like_url(".")


def _git_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    env = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"]
    subprocess.run(["git", *env, "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", *env, "add", "."], cwd=path, check=True)
    subprocess.run(["git", *env, "commit", "-q", "-m", "one"], cwd=path, check=True)
    return path


def test_clone_then_update_with_git(tmp_path):
    src = _git_repo(tmp_path / "src")
    dest, log = tmp_path / "clone", []
    remote.fetch(src.as_uri(), dest)
    assert (dest / "app.py").exists() and (dest / ".git").exists()
    # the high-level call sees a clone already there and fast-forwards it instead
    (src / "more.py").write_text("x = 1\n", encoding="utf-8")
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "add", "."], cwd=src, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "two"], cwd=src, check=True)
    assert remote.clone("https://github.com/o/r", log=log.append, dest=dest) == dest
    assert log == [f"updating {dest}"] and (dest / "more.py").exists()
    # a folder that is not a clone is never written into
    other = tmp_path / "other"
    other.mkdir()
    (other / "x").write_text("x", encoding="utf-8")
    with pytest.raises(RuntimeError, match="not a git clone"):
        remote.clone("https://github.com/o/r", dest=other)


def test_big_repositories_are_refused_before_checkout(tmp_path, monkeypatch):
    """The files are measured from the index after a no-checkout clone; above the cap nothing is written."""
    src = _git_repo(tmp_path / "src")
    (src / "blob.bin").write_bytes(b"\0" * 2_500_000)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "add", "."], cwd=src, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "big"], cwd=src, check=True)
    monkeypatch.setenv("LANTERN_CLONE_MAX_MB", "2")
    dest = tmp_path / "dest"
    with pytest.raises(RuntimeError, match="above Lantern's 2 MB limit"):
        remote.fetch(src.as_uri(), dest)
    assert not dest.exists()
    monkeypatch.setenv("LANTERN_CLONE_MAX_MB", "0")   # no cap
    remote.fetch(src.as_uri(), dest)
    assert (dest / "blob.bin").stat().st_size == 2_500_000 and (dest / "app.py").exists()
    assert subprocess.run(["git", "status", "--porcelain"], cwd=dest, capture_output=True, text=True).stdout == ""


def test_failed_clone_has_a_plain_message_and_no_credentials(tmp_path):
    with pytest.raises(RuntimeError) as e:
        remote.fetch((tmp_path / "nowhere").as_uri(), tmp_path / "dest")
    assert "could not clone it" in str(e.value) and "clone it yourself" in str(e.value)
    assert "tok" not in remote._tail("fatal: unable to access 'https://me:tok@github.com/o/r/': 401")


def test_cli_analyzes_a_link(tmp_path, monkeypatch, capsys):
    def fake_clone(link, log=None, dest=None, root=None):
        remote.parse(link)   # the real link check, then a copy of the fixture instead of git
        d = tmp_path / "repos" / "shop"
        shutil.copytree(FIX / "shop", d)
        (log or print)("cloning (fake)")
        return d
    monkeypatch.setattr(remote, "clone", fake_clone)
    assert main(["analyze", "https://github.com/wakil/shop", "--offline"]) == 0
    assert (tmp_path / "repos" / "shop" / ".lantern" / "report.html").exists()
    assert "cloning (fake)" in capsys.readouterr().err
    assert main(["analyze", "https://github.com/wakil", "--offline"]) == 2   # a bad link is an error, not "not a folder"
    assert "not a repository link" in capsys.readouterr().err


def test_app_clones_a_link_in_a_job(srv, tmp_path, monkeypatch):  # noqa: F811
    base, store = srv
    calls = []

    def fake_fetch(url, dest, branch=None, timeout=900):
        calls.append((url, branch))
        shutil.copytree(FIX / "shop", dest, dirs_exist_ok=True)
    monkeypatch.setattr(remote, "fetch", fake_fetch)
    code, r = call(base, "/api/projects", "POST", {"path": "https://github.com/wakil/shop/tree/main"})
    assert code == 202 and r["job"]["kind"] == "clone" and r["project"]["name"] == "shop"
    assert r["project"]["path"] == str(store.root / "repos" / "github.com" / "wakil" / "shop")
    j = wait(base, r["job"]["id"])
    assert j["status"] == "done", j
    assert calls == [("https://github.com/wakil/shop", "main")] and "cloning https://github.com/wakil/shop (branch main)" in j["log"][0]
    _, st = call(base, "/api/state")
    p = next(x for x in st["projects"] if x["id"] == r["project"]["id"])
    assert p["has_report"] and p["grade"] == "F" and p["shape"] == "full-stack web app"
    # a bad link is refused up front
    assert call(base, "/api/projects", "POST", {"path": "https://me:tok@github.com/o/r"})[0] == 400
    # a clone that fails forgets the project again and leaves no folder behind
    def failing(url, dest, branch=None, timeout=900):
        raise RuntimeError("could not clone it: repository not found")
    monkeypatch.setattr(remote, "fetch", failing)
    code, r = call(base, "/api/projects", "POST", {"path": "https://github.com/wakil/private"})
    assert code == 202
    j = wait(base, r["job"]["id"])
    assert j["status"] == "error" and "repository not found" in j["error"]
    assert not store.project(r["project"]["id"]) and not (store.root / "repos" / "github.com" / "wakil" / "private").exists()
