"""The website's list of the signed-in person's GitHub repositories (2026-11-17): only repositories GitHub says
their account owns, private ones only where they installed the app on that account, nothing stored."""

import sys
import tempfile
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

from lantern_cloud import ghapp  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

TOKEN = "ghs_" + "y" * 36


@pytest.fixture(scope="module")
def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode(), k.public_key()


def repo(name, owner_id=7, private=False, pushed="2026-11-10T00:00:00Z", **more):
    return {"full_name": name, "owner": {"id": owner_id}, "private": private, "pushed_at": pushed,
            "description": "d", "language": "Python", **more}


def github(pub=None, installed=True, inst_owner=7, public=None, installed_repos=None, status=200):
    calls = []
    public = public if public is not None else [repo("octo/shop", pushed="2026-11-01T00:00:00Z"),
                                                repo("other/fork", owner_id=8)]
    installed_repos = installed_repos if installed_repos is not None else [
        repo("octo/secret", private=True, pushed="2026-11-15T00:00:00Z"), repo("octo/shop")]

    def handle(req: httpx.Request):
        calls.append((req.method, req.url.path, dict(req.url.params), req.headers.get("authorization", "")))
        if status != 200:
            return httpx.Response(status, json={})
        if req.url.path == "/users/octo/installation":
            jwt.decode(req.headers["authorization"].split(" ", 1)[1], pub, algorithms=["RS256"])
            return httpx.Response(200, json={"id": 5, "account": {"id": inst_owner}}) if installed else httpx.Response(404, json={})
        if req.url.path == "/app/installations/5/access_tokens":
            return httpx.Response(201, json={"token": TOKEN})
        if req.url.path == "/installation/repositories":
            assert req.headers["authorization"] == f"token {TOKEN}"
            return httpx.Response(200, json={"repositories": installed_repos})
        if req.url.path == "/users/octo/repos":
            return httpx.Response(200, json=public)
        return httpx.Response(500)
    return httpx.MockTransport(handle), calls


def test_without_the_app_only_the_persons_own_public_repositories_are_listed():
    t, calls = github()
    d = ghapp.your_repos(None, "github:7", "github:octo", transport=t)
    assert [r["name"] for r in d["repos"]] == ["octo/shop"] and d["connected"] is False
    assert calls[-1][2] == {"type": "owner", "sort": "pushed", "per_page": "100", "page": "1"}


def test_with_the_app_installed_private_repositories_are_listed_newest_first(key):
    t, _ = github(key[1])
    app = ghapp.GitHubApp("123", key[0], "lantern-checks", transport=t)
    d = ghapp.your_repos(app, "github:7", "github:octo")
    assert [(r["name"], r["private"]) for r in d["repos"]] == [("octo/secret", True), ("octo/shop", False)]
    assert d["connected"] is True and TOKEN not in str(d)


def test_an_installation_of_someone_else_lists_no_private_repository(key):
    t, _ = github(key[1], inst_owner=99)        # a renamed login now names another account
    app = ghapp.GitHubApp("123", key[0], "lantern-checks", transport=t)
    d = ghapp.your_repos(app, "github:7", "github:octo")
    assert [r["name"] for r in d["repos"]] == ["octo/shop"] and d["connected"] is False


def test_odd_rows_are_passed_over():
    bad = [repo("octo/a b"), repo("octo/../x"), {"full_name": "octo/x"}, "nope", repo("octo/ok", description=7)]
    t, _ = github(public=bad)
    d = ghapp.your_repos(None, "github:7", "github:octo", transport=t)
    assert [(r["name"], r["description"]) for r in d["repos"]] == [("octo/ok", "")]


@pytest.mark.parametrize("account,label", [("google:1", "google:x"), ("github:7", "github:bad/login"), ("github:7", None)])
def test_no_github_sign_in_lists_nothing(account, label):
    with pytest.raises(ghapp.NoAccess):
        ghapp.your_repos(None, account, label, transport=github()[0])


def test_github_down_or_limited_is_said():
    for status in (403, 500):
        with pytest.raises(ghapp.GitHubDown):
            ghapp.your_repos(None, "github:7", "github:octo", transport=github(status=status)[0])


def make(tmp_path, label="github:octo", account="github:7"):
    gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db")))
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "cloud.db"),
                 results_dir=str(tmp_path / "results"), work_dir=tempfile.mkdtemp(prefix="lantern-cloud-test-"),
                 audits=False)
    cloud = TestClient(create_app(s, transport=httpx.ASGITransport(app=gw_app), start_worker=False))
    return cloud, gw_app.state.store.sign_in(account, label)


def test_the_route_lists_and_keeps_the_list_for_a_moment(tmp_path, monkeypatch):
    asked = []

    def fake(app, account, label):
        asked.append((account, label))
        return {"repos": [{"name": "octo/shop", "private": False, "description": "", "language": "", "pushed": ""}],
                "connected": False}
    monkeypatch.setattr(ghapp, "your_repos", fake)
    cloud, tok = make(tmp_path)
    h = {"authorization": f"Bearer {tok}"}
    a = cloud.get("/v1/github/repos", headers=h).json()
    b = cloud.get("/v1/github/repos", headers=h).json()
    assert a == b and a["github"] is True and a["repos"][0]["name"] == "octo/shop"
    assert asked == [("github:7", "github:octo")]
    cloud.get("/v1/github/repos?fresh=1", headers=h)
    assert len(asked) == 2
    assert cloud.get("/v1/github/repos").status_code == 401


def test_the_route_for_a_google_sign_in_and_when_github_is_down(tmp_path, monkeypatch):
    cloud, tok = make(tmp_path, label="google:x", account="google:1")
    assert cloud.get("/v1/github/repos", headers={"authorization": f"Bearer {tok}"}).json()["github"] is False

    def down(*a):
        raise ghapp.GitHubDown(500)
    monkeypatch.setattr(ghapp, "your_repos", down)
    (tmp_path / "2").mkdir()
    cloud, tok = make(tmp_path / "2")
    r = cloud.get("/v1/github/repos", headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 503 and "Paste" in r.json()["error"]["message"]


def test_the_page_lists_projects_and_the_github_icon_is_sized():
    page = (ROOT / "cloud" / "lantern_cloud" / "site" / "index.html").read_text(encoding="utf-8")
    assert "/v1/github/repos" in page and "data-repo=" in page
    assert "${GH}<input" not in page          # an unsized GitHub mark filled the whole screen (2026-11-17)
