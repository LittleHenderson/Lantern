"""Cloud service, milestone 4: the website. It is built from the app's own page, so it looks and works like the app;
it signs people in through the gateway with an HttpOnly cookie; nothing another site does can act for them."""

import json
import re
import shutil
import subprocess
import sys
from http.cookies import SimpleCookie
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "cloud"))
from fastapi.testclient import TestClient  # noqa: E402

from lantern_cloud import site  # noqa: E402
from lantern_cloud.app import create_app  # noqa: E402
from lantern_cloud.settings import Settings  # noqa: E402
from lantern_gateway.app import Settings as GwSettings  # noqa: E402
from lantern_gateway.app import create_app as create_gateway  # noqa: E402

APP_HTML = (site._viewer() / "app.html").read_text(encoding="utf-8")
SITE = {"x-lantern-site": "1"}


@pytest.fixture
def env(tmp_path):
    gw_app = create_gateway(GwSettings(admin_secret="a" * 24, db_path=str(tmp_path / "gw.db"),
                                       github_client_id="id", github_client_secret="secret"))
    s = Settings(gateway_url="http://gateway.test/v1", public_url="https://lantern.example", db_path=str(tmp_path / "c.db"),
                 results_dir=str(tmp_path / "r"), work_dir=str(tmp_path / "w"), audits=False)
    app = create_app(s, transport=httpx.ASGITransport(app=gw_app), start_worker=False)
    return TestClient(app, base_url="https://lantern.example"), gw_app.state.store, app


def set_cookies(resp) -> dict:
    out = {}
    for h in resp.headers.get_list("set-cookie"):
        c = SimpleCookie(); c.load(h)
        for k, m in c.items():
            out[k] = {"value": m.value, "httponly": "httponly" in h.lower(), "secure": "secure" in h.lower(),
                      "samesite": (re.search(r"samesite=(\w+)", h, re.I) or [None, None])[1], "path": m["path"],
                      "max_age": m["max-age"]}
    return out


# ---- built from the app ----
def test_the_website_uses_the_apps_own_style_mark_icons_and_backdrop():
    parts = site.app_parts(APP_HTML)
    html, nonce = site.page("9.9.9")
    assert parts["style"].strip() and parts["style"] in html              # the app's stylesheet, whole and unchanged
    assert parts["fonts"] in html and parts["brand"] in html
    for piece in ("const esc = ", "const ICONS = {", "function ring(", "function applyTheme()", "(function backdrop()"):
        assert piece in parts["js"] and piece in html
    assert "__APP_" not in html and "__VERSION__" not in html and "9.9.9" in html
    # every script carries this response's nonce; no inline handlers (the policy would refuse them anyway)
    tags = re.findall(r"<script[^>]*>", html)
    assert tags and all(f'nonce="{nonce}"' in t for t in tags)
    assert not re.search(r"<[^>]+\son[a-z]+\s*=", html.split("<script", 1)[0])


def test_app_parts_says_so_when_the_app_changes_shape():
    with pytest.raises(ValueError, match="changed shape"):
        site.app_parts(APP_HTML.replace("// Icons: fixed markup, never data.", "// icons"))


def test_the_websites_script_parses(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    html, _ = site.page("1")
    js = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", html, re.S))
    f = tmp_path / "site.js"
    f.write_text(js, encoding="utf-8")
    r = subprocess.run([node, "--check", str(f)], capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0, r.stderr


def test_page_and_pwa_files(env):
    c, _, _ = env
    r = c.get("/")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    csp = r.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    assert f'nonce="{nonce}"' in r.text and "frame-ancestors 'self'" in csp and "connect-src 'self'" in csp
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"
    assert c.get("/").headers["content-security-policy"] != csp              # a fresh nonce every time
    m = c.get("/manifest.webmanifest")
    assert m.headers["content-type"].startswith("application/manifest+json")
    man = json.loads(m.text)
    assert man["start_url"] == "/" and man["display"] == "standalone"
    assert c.get("/icon.svg").content == (site._viewer() / "icon.svg").read_bytes()
    sw = c.get("/sw.js")
    assert sw.headers["content-type"].startswith("text/javascript") and "/v1/" in sw.text   # says it never stores those
    assert c.get("/cloud.db").status_code == 404 and c.get("/app.html").status_code == 404


# ---- sign-in ----
def test_sign_in_through_the_gateway_puts_the_token_in_an_httponly_cookie(env):
    c, gw, _ = env
    assert c.get("/v1/signin/providers").json() == {"providers": ["github"]}
    assert c.post("/v1/signin/start", json={"provider": "github"}).status_code == 403       # not from our page
    assert c.post("/v1/signin/start", json={"provider": "google"}, headers=SITE).status_code == 400   # not switched on
    r = c.post("/v1/signin/start", json={"provider": "github"}, headers=SITE)
    assert r.status_code == 200
    ck = set_cookies(r)["lsi"]
    assert ck["httponly"] and ck["secure"] and ck["samesite"].lower() == "strict" and ck["path"] == "/v1/signin"
    cli = ck["value"]
    assert r.json()["url"] == f"http://gateway.test/v1/auth/github/start?cli={cli}"
    assert cli not in json.dumps(r.json()).replace(r.json()["url"], "")
    # still signing in
    assert c.post("/v1/signin/poll", headers=SITE).json() == {"signed_in": False}
    # the gateway's callback parks the token under the code; the next poll collects it into a cookie
    tok = gw.sign_in("github:7", "github:octo")
    gw.park(cli, tok)
    r = c.post("/v1/signin/poll", headers=SITE)
    assert r.json() == {"signed_in": True, "label": "github:octo"} and tok not in r.text
    lt = set_cookies(r)["lt"]
    assert lt["value"] == tok and lt["httponly"] and lt["secure"] and lt["samesite"].lower() == "strict" and lt["path"] == "/"
    me = c.get("/v1/me")
    assert me.status_code == 200 and me.json()["label"] == "github:octo"
    # the code is spent and its cookie gone
    assert c.post("/v1/signin/poll", headers=SITE).status_code == 400
    # sign out
    assert c.post("/v1/signout").status_code == 403
    assert c.post("/v1/signout", headers=SITE).status_code == 200
    assert c.get("/v1/me").status_code == 401


def test_another_browser_cannot_collect_someone_elses_sign_in(env):
    c, gw, app = env
    r = c.post("/v1/signin/start", json={"provider": "github"}, headers=SITE)
    cli = set_cookies(r)["lsi"]["value"]
    gw.park(cli, gw.sign_in("github:7", "github:octo"))
    other = TestClient(app, base_url="https://lantern.example")
    assert other.post("/v1/signin/poll", headers=SITE).status_code == 400      # no code of its own
    other.cookies.set("lsi", "x" * 48, domain="lantern.example", path="/v1/signin")
    assert other.post("/v1/signin/poll", headers=SITE).json() == {"signed_in": False}


def test_cookie_requests_that_change_something_need_the_sites_header(env):
    c, gw, _ = env
    tok = gw.sign_in("github:7", "github:octo")
    c.cookies.set("lt", tok, domain="lantern.example", path="/")
    assert c.get("/v1/me").status_code == 200 and c.get("/v1/runs").status_code == 200
    # a form or link on another site would carry the cookie (if the browser sent it) but never this header
    r = c.post("/v1/repos", json={"link": "https://github.com/octo/shop"})
    assert r.status_code == 403 and r.json()["error"]["type"] == "forbidden"
    r = c.post("/v1/repos", json={"link": "https://github.com/octo/shop"}, headers=SITE)
    assert r.status_code == 503          # past the sign-in check: this test server has no worker
    # a Bearer token (apps, scripts) needs no header, as before
    c.cookies.clear()
    assert c.post("/v1/repos", json={"link": "https://github.com/octo/shop"},
                  headers={"authorization": f"Bearer {tok}"}).status_code == 503


def test_sign_in_unavailable_is_said_plainly(tmp_path):
    def down(request):
        raise httpx.ConnectError("no route")
    s = Settings(gateway_url="http://gateway.test/v1", db_path=str(tmp_path / "c.db"), results_dir=str(tmp_path / "r"),
                 work_dir=str(tmp_path / "w"))
    c = TestClient(create_app(s, transport=httpx.MockTransport(down), start_worker=False))
    r = c.get("/v1/signin/providers")
    assert r.status_code == 503 and "unavailable" in r.json()["error"]["message"]


def test_run_view_names_the_step(env):
    from lantern_cloud.app import run_view
    from lantern_cloud.worker import STAGES
    r = {"id": "x", "link": "l", "host": "h", "privacy": "structure", "status": "running", "stage": STAGES["audit"],
         "error": None, "created": "", "started": "", "finished": None, "commit_sha": None, "summary": None,
         "share_slug": None, "log_tail": ""}
    assert run_view(r)["step"] == "audit"
    assert run_view({**r, "stage": "something else"})["step"] is None


def test_summary_keeps_only_well_formed_values(tmp_path):
    from lantern_cloud.worker import _summary
    bad = "<img src=x onerror=alert(1)>"
    (tmp_path / "readiness.json").write_text(json.dumps({"score": bad, "grade": bad, "shape": bad * 20}), encoding="utf-8")
    (tmp_path / "security.json").write_text(json.dumps({"counts": {"critical": bad, "high": "3", "medium": -2}}), encoding="utf-8")
    (tmp_path / "graph.json").write_text(json.dumps({"meta": {"files": bad}}), encoding="utf-8")
    s = _summary(tmp_path)
    assert s["score"] is None and s["grade"] is None and s["files"] is None and len(s["shape"]) == 80
    assert s["counts"] == {"critical": 0, "high": 3, "medium": 0, "low": 0}
