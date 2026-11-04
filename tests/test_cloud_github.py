"""Connect GitHub: a private repository the person chose on GitHub is read with a one-repository, read-only token,
and only for someone GitHub says may read it. The token never reaches a link, a file or a log."""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from lantern import remote  # noqa: E402
from lantern_cloud import ghapp  # noqa: E402
from lantern_cloud import worker as worker_mod  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

LINK = "https://github.com/octo/secret-shop"
TOKEN = "ghs_" + "x" * 36          # what GitHub hands out; built here, never a real one


@pytest.fixture(scope="module")
def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    return pem, k.public_key()


def fake_github(pub, installed=True, in_install=True, reader_id=7, permission="read"):
    calls = []

    def handle(req: httpx.Request):
        calls.append((req.method, req.url.path))
        auth = req.headers.get("authorization", "")
        if req.url.path.startswith("/repos/octo/secret-shop/installation") or req.url.path.startswith("/app/"):
            claims = jwt.decode(auth.split(" ", 1)[1], pub, algorithms=["RS256"])
            assert claims["iss"] == "123" and claims["exp"] - claims["iat"] <= 600
        if req.url.path == "/repos/octo/secret-shop/installation":
            return httpx.Response(200 if installed else 404, json={"id": 99} if installed else {})
        if req.url.path == "/app/installations/99/access_tokens":
            body = json.loads(req.content)
            assert body == {"repositories": ["secret-shop"], "permissions": {"contents": "read", "metadata": "read"}}
            return httpx.Response(201, json={"token": TOKEN}) if in_install else httpx.Response(422, json={})
        if req.url.path == "/repos/octo/secret-shop/collaborators/octo/permission":
            assert auth == f"token {TOKEN}"
            if reader_id is None:
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"permission": permission, "user": {"id": reader_id, "login": "octo"}})
        return httpx.Response(500)
    return httpx.MockTransport(handle), calls


def app_with(key, **kw):
    transport, calls = fake_github(key[1], **kw)
    return ghapp.GitHubApp("123", key[0], "lantern-checks", transport=transport), calls


def test_a_reader_gets_a_read_only_token_for_that_one_repository(key):
    gh, calls = app_with(key)
    assert gh.token_for("octo", "secret-shop", "github:7", "github:octo") == TOKEN
    assert [p for _, p in calls] == ["/repos/octo/secret-shop/installation", "/app/installations/99/access_tokens",
                                     "/repos/octo/secret-shop/collaborators/octo/permission"]
    assert gh.install_url == "https://github.com/apps/lantern-checks/installations/new"


@pytest.mark.parametrize("kw,account,label,kind", [
    ({"installed": False}, "github:7", "github:octo", "connect"),            # app not on this repository
    ({"in_install": False}, "github:7", "github:octo", "connect"),           # installed, this repository not chosen
    ({"reader_id": None}, "github:7", "github:octo", "denied"),              # not a collaborator
    ({"reader_id": 8}, "github:7", "github:octo", "denied"),                 # the login now belongs to someone else
    ({"permission": "none"}, "github:7", "github:octo", "denied"),
    ({}, "google:abc", "google:abc", "github"),                               # GitHub cannot vouch for a Google sign-in
])
def test_anyone_else_is_refused(key, kw, account, label, kind):
    gh, _ = app_with(key, **kw)
    with pytest.raises(ghapp.NoAccess) as e:
        gh.token_for("octo", "secret-shop", account, label)
    assert e.value.kind == kind


def test_git_gets_the_token_only_in_its_environment():
    env = remote._auth_env("https://github.com/octo/secret-shop", TOKEN)
    assert env["GIT_CONFIG_COUNT"] == "1" and env["GIT_CONFIG_KEY_0"] == "http.https://github.com/.extraHeader"
    assert env["GIT_CONFIG_VALUE_0"] == "Authorization: Basic " + base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()


def test_a_token_clone_sends_the_header_and_keeps_it_out_of_the_clone(tmp_path, monkeypatch):
    seen = {}

    def fake_git(args, cwd, timeout=900, env=None):
        seen["args"], seen["env"] = args, env
        dest = Path(args[-1])
        (dest / ".git").mkdir(parents=True)
        return subprocess.CompletedProcess(args, 1, "", "stop here")
    monkeypatch.setattr(remote, "_git", fake_git)
    with pytest.raises(RuntimeError):
        remote.fetch("https://github.com/octo/secret-shop", tmp_path / "repo", auth=TOKEN)
    assert TOKEN not in " ".join(seen["args"]) and "GIT_CONFIG_VALUE_0" in seen["env"]
    assert not (tmp_path / "repo").exists()


# ---- the worker, end to end (the clone is a local git clone; GitHub is replaced) ----
def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, encoding="utf-8")


@pytest.fixture(scope="module")
def origin(tmp_path_factory):
    src = tmp_path_factory.mktemp("origin") / "shop"
    shutil.copytree(ROOT / "tests" / "fixtures" / "shop", src)
    git("init", "-q", "-b", "main", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", "-A", cwd=src)
    git("-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "x", cwd=src)
    return src


def make(tmp_path, key, monkeypatch, origin, outcome):
    """A cloud service with Connect GitHub on; the anonymous clone fails as a private repository does, a clone with
    the token succeeds. `outcome`: the token, or the NoAccess kind the app answers with."""
    def clone(link, dest, log, token=None):
        if token is None:
            raise RuntimeError("could not clone it: fatal: could not read Username for 'https://github.com': "
                               "terminal prompts disabled. If the repository is private, clone it yourself and add the folder.")
        assert token == TOKEN
        log(f"cloning {link} with {token}")          # a careless log line: the worker hides the token
        git("clone", "-q", "--depth", "1", origin.as_uri(), str(dest), cwd=dest.parent)
        return dest

    def token_for(self, owner, repo, account, label):
        assert (owner, repo, account, label) == ("octo", "secret-shop", "github:7", "github:octo")
        if outcome != TOKEN:
            raise ghapp.NoAccess(outcome)
        return TOKEN
    monkeypatch.setattr(worker_mod, "clone_repo", clone)
    monkeypatch.setattr(ghapp.GitHubApp, "token_for", token_for)
    gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")))
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "cloud.db"),
                 results_dir=str(tmp_path / "results"), work_dir=tempfile.mkdtemp(prefix="lantern-cloud-test-"),
                 audits=False, github_app_id="123", github_app_key=key[0], github_app_slug="lantern-checks")
    cloud = TestClient(create_app(s, transport=httpx.ASGITransport(app=gw_app)))
    return cloud, gw_app.state.store.sign_in("github:7", "github:octo")


def run(cloud, tok):
    h = {"authorization": f"Bearer {tok}"}
    rid = cloud.post("/v1/repos", json={"link": LINK}, headers=h).json()["id"]
    end = time.time() + 120
    while time.time() < end:
        r = cloud.get(f"/v1/runs/{rid}", headers=h).json()
        if r["status"] in ("done", "error", "blocked"):
            return r
        time.sleep(0.3)
    raise AssertionError("run did not finish")


@pytest.mark.skipif(os.name != "posix", reason="the cloud worker runs on Linux")
def test_a_connected_private_repository_is_checked(tmp_path, key, monkeypatch, origin):
    cloud, tok = make(tmp_path, key, monkeypatch, origin, TOKEN)
    me = cloud.get("/v1/me", headers={"authorization": f"Bearer {tok}"}).json()
    assert me["connect_url"] == "https://github.com/apps/lantern-checks/installations/new"
    r = run(cloud, tok)
    assert r["status"] == "done", r
    assert "your GitHub connection" in r["log_tail"] and TOKEN not in json.dumps(r)


@pytest.mark.skipif(os.name != "posix", reason="the cloud worker runs on Linux")
@pytest.mark.parametrize("kind,error,hint", [("connect", worker_mod.CONNECT, "connect"),
                                             ("denied", worker_mod.NO_ACCESS, "upload"),
                                             ("github", worker_mod.GITHUB_ONLY, "upload")])
def test_a_private_repository_that_is_not_connected_says_what_to_do(tmp_path, key, monkeypatch, origin, kind, error, hint):
    cloud, tok = make(tmp_path, key, monkeypatch, origin, kind)
    r = run(cloud, tok)
    assert r["status"] == "error" and r["error"] == error and r["hint"] == hint


def test_connect_github_is_off_without_all_three_settings(key):
    assert Settings(github_app_id="123", github_app_key=key[0], github_app_slug="").github_app() is None
    assert Settings(github_app_id="123", github_app_key=key[0], github_app_slug="x").github_app() is not None
